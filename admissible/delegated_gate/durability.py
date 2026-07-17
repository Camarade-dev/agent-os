"""Shared durable-publication policy for delegated and native state.

The adapter deliberately separates file-content durability, name visibility,
and publication-metadata durability.  A visible final path is never returned
as successful unless the platform publication boundary and an exact byte
reload both complete.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, BinaryIO, Callable, Mapping


MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_WRITE_THROUGH = 0x00000008
WINDOWS_MOVEFILEEX_PROFILE = (
    "admissible_platform_durability_windows_movefileex_write_through_v1"
)
POSIX_FSYNC_PROFILE = "admissible_platform_durability_posix_file_and_directory_fsync_v1"


class PublicationMode(str, Enum):
    CREATE_ONLY = "CREATE_ONLY"
    REPLACE_EXISTING = "REPLACE_EXISTING"


class ReplacementAuthority(str, Enum):
    CAS_LOCK_HELD_AFTER_VALIDATION = "CAS_LOCK_HELD_AFTER_VALIDATION"
    CAPABILITY_PROBE = "CAPABILITY_PROBE"


class FileContentDurability(str, Enum):
    FILE_CONTENT_DURABLE = "FILE_CONTENT_DURABLE"


class PublicationVisibility(str, Enum):
    PUBLICATION_VISIBLE = "PUBLICATION_VISIBLE"


class PublicationMetadataDurability(str, Enum):
    PUBLICATION_METADATA_DURABLE = "PUBLICATION_METADATA_DURABLE"
    PUBLICATION_METADATA_UNSUPPORTED = "PUBLICATION_METADATA_UNSUPPORTED"
    PUBLICATION_METADATA_UNCERTAIN = "PUBLICATION_METADATA_UNCERTAIN"


@dataclass(frozen=True)
class DurablePublicationResult:
    platform: str
    profile_id: str
    mode: PublicationMode
    final_path: str
    byte_count: int
    sha256: str
    file_content: FileContentDurability
    visibility: PublicationVisibility
    metadata: PublicationMetadataDurability


class DurabilityAdapterError(RuntimeError):
    reason_code = "DURABILITY_ADAPTER_ERROR"

    def __init__(
        self,
        message: str,
        *,
        path: Path,
        original_error: BaseException | None = None,
        file_content_durable: bool = False,
        publication_visible: bool = False,
        metadata_status: PublicationMetadataDurability | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.original_error = original_error
        self.file_content_durable = file_content_durable
        self.publication_visible = publication_visible
        self.metadata_status = metadata_status
        self.os_error_code = (
            getattr(original_error, "winerror", None)
            or getattr(original_error, "errno", None)
            or getattr(original_error, "os_error_code", None)
        )

    def to_diagnostic(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "file_content_durable": self.file_content_durable,
            "publication_visible": self.publication_visible,
            "metadata_status": self.metadata_status.value if self.metadata_status else None,
            "os_error_code": self.os_error_code,
        }


class PublicationPathInvalid(DurabilityAdapterError):
    reason_code = "PUBLICATION_PATH_INVALID"


class TemporaryFileCreateFailure(DurabilityAdapterError):
    reason_code = "TEMPORARY_FILE_CREATE_FAILURE"


class FileWriteFailure(DurabilityAdapterError):
    reason_code = "FILE_WRITE_FAILURE"


class FileFlushFailure(DurabilityAdapterError):
    reason_code = "FILE_FLUSH_FAILURE"


class FileDurableFlushFailure(DurabilityAdapterError):
    reason_code = "FILE_DURABLE_FLUSH_FAILURE"


class PublicationConflict(DurabilityAdapterError):
    reason_code = "PUBLICATION_CONFLICT"


class PublicationApiUnavailable(DurabilityAdapterError):
    reason_code = "PUBLICATION_API_UNAVAILABLE"


class SameVolumeRequired(DurabilityAdapterError):
    reason_code = "SAME_VOLUME_REQUIRED"


class PublicationFailureBeforeVisibility(DurabilityAdapterError):
    reason_code = "PUBLICATION_API_FAILURE_BEFORE_VISIBILITY"


class PublicationVisibleButMetadataUncertain(DurabilityAdapterError):
    reason_code = "PUBLICATION_VISIBLE_METADATA_UNCERTAIN"


class PostPublicationReloadFailure(DurabilityAdapterError):
    reason_code = "POST_PUBLICATION_RELOAD_FAILURE"


class PostPublicationFingerprintMismatch(PostPublicationReloadFailure):
    reason_code = "POST_PUBLICATION_FINGERPRINT_MISMATCH"


class TemporaryCleanupFailure(DurabilityAdapterError):
    reason_code = "TEMPORARY_CLEANUP_FAILURE"


class WindowsMoveFileError(OSError):
    def __init__(self, error_code: int, message: str) -> None:
        super().__init__(error_code, message)
        self.error_code = error_code
        self.winerror = error_code


def _default_write(handle: BinaryIO, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = handle.write(remaining)
        if not isinstance(written, int) or written <= 0:
            raise OSError("file write did not make forward progress")
        remaining = remaining[written:]


def _default_move_file_ex(source: Path, destination: Path, flags: int) -> None:
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file_ex = kernel32.MoveFileExW
        move_file_ex.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
        move_file_ex.restype = wintypes.BOOL
    except (AttributeError, ImportError, OSError) as exc:
        raise PublicationApiUnavailable(
            "MoveFileExW is unavailable",
            path=destination,
            original_error=exc,
            file_content_durable=True,
            metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNSUPPORTED,
        ) from exc
    ctypes.set_last_error(0)
    if not move_file_ex(str(source), str(destination), flags):
        error_code = int(ctypes.get_last_error())
        try:
            message = ctypes.FormatError(error_code).strip()
        except (AttributeError, OSError):
            message = "MoveFileExW failed"
        raise WindowsMoveFileError(error_code, message)


def _is_redirecting(path: Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    if int(getattr(metadata, "st_file_attributes", 0)) & reparse:
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction is not None and isjunction(os.fspath(path)))


def _canonical_parent(path: Path) -> Path:
    if not path.is_absolute() or "\x00" in os.fspath(path):
        raise PublicationPathInvalid("publication path must be absolute", path=path)
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute != path or not path.name or path.name in {".", ".."}:
        raise PublicationPathInvalid("publication path must be canonical", path=path)
    try:
        parent = path.parent.resolve(strict=True)
        metadata = os.lstat(path.parent)
    except OSError as exc:
        raise PublicationPathInvalid(
            "publication parent cannot be resolved", path=path, original_error=exc
        ) from exc
    if parent != path.parent or not stat.S_ISDIR(metadata.st_mode) or _is_redirecting(path.parent, metadata):
        raise PublicationPathInvalid(
            "publication parent must be a canonical non-redirecting directory", path=path
        )
    return parent


def _same_volume(source: Path, destination: Path) -> bool:
    source_drive = os.path.splitdrive(os.fspath(source))[0].casefold()
    destination_drive = os.path.splitdrive(os.fspath(destination))[0].casefold()
    if source_drive != destination_drive:
        return False
    try:
        return int(os.stat(source).st_dev) == int(os.stat(destination.parent).st_dev)
    except OSError:
        return False


class PlatformDurabilityAdapter:
    """One production algorithm with narrow injectable OS primitives for tests."""

    _WINDOWS_CONFLICTS = frozenset({80, 183})
    _WINDOWS_UNSUPPORTED = frozenset({1, 50, 120, 127})

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        writer: Callable[[BinaryIO, bytes], None] = _default_write,
        flusher: Callable[[BinaryIO], Any] | None = None,
        file_sync: Callable[[int], Any] = os.fsync,
        windows_move: Callable[[Path, Path, int], None] = _default_move_file_ex,
        posix_link: Callable[[str | Path, str | Path], Any] = os.link,
        posix_replace: Callable[[str | Path, str | Path], Any] = os.replace,
        directory_open: Callable[[str | Path, int], int] = os.open,
        directory_sync: Callable[[int], Any] = os.fsync,
        closer: Callable[[int], Any] = os.close,
        unlinker: Callable[[str | Path], Any] = os.unlink,
    ) -> None:
        self.platform_name = os.name if platform_name is None else platform_name
        if self.platform_name not in {"nt", "posix"}:
            raise ValueError("unsupported durability platform")
        self.writer = writer
        self.flusher = flusher or (lambda handle: handle.flush())
        self.file_sync = file_sync
        self.windows_move = windows_move
        self.posix_link = posix_link
        self.posix_replace = posix_replace
        self.directory_open = directory_open
        self.directory_sync = directory_sync
        self.closer = closer
        self.unlinker = unlinker

    @property
    def profile_id(self) -> str:
        return WINDOWS_MOVEFILEEX_PROFILE if self.platform_name == "nt" else POSIX_FSYNC_PROFILE

    @staticmethod
    def _cleanup(path: Path) -> OSError | None:
        if not os.path.lexists(path):
            return None
        try:
            os.unlink(path)
        except OSError as exc:
            return exc
        return None

    def _fail_before_visibility(
        self,
        error_type: type[DurabilityAdapterError],
        message: str,
        *,
        final_path: Path,
        temporary: Path | None,
        original_error: BaseException,
        file_content_durable: bool = False,
        metadata_status: PublicationMetadataDurability | None = None,
    ) -> None:
        cleanup_error = self._cleanup(temporary) if temporary is not None else None
        if cleanup_error is not None:
            raise TemporaryCleanupFailure(
                "temporary publication file could not be removed",
                path=final_path,
                original_error=cleanup_error,
                file_content_durable=file_content_durable,
                metadata_status=metadata_status,
            ) from original_error
        raise error_type(
            message,
            path=final_path,
            original_error=original_error,
            file_content_durable=file_content_durable,
            metadata_status=metadata_status,
        ) from original_error

    def _publish_posix(self, temporary: Path, final_path: Path, mode: PublicationMode) -> None:
        if mode is PublicationMode.CREATE_ONLY:
            self.posix_link(temporary, final_path)
            try:
                self.unlinker(temporary)
            except OSError as exc:
                raise PublicationVisibleButMetadataUncertain(
                    "create-only name is visible but temporary-name cleanup is uncertain",
                    path=final_path,
                    original_error=exc,
                    file_content_durable=True,
                    publication_visible=True,
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                ) from exc
        else:
            self.posix_replace(temporary, final_path)
        directory_fd: int | None = None
        try:
            directory_fd = self.directory_open(final_path.parent, os.O_RDONLY)
            self.directory_sync(directory_fd)
        except OSError as exc:
            raise PublicationVisibleButMetadataUncertain(
                "publication is visible but parent-directory durability is uncertain",
                path=final_path,
                original_error=exc,
                file_content_durable=True,
                publication_visible=True,
                metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
            ) from exc
        finally:
            if directory_fd is not None:
                try:
                    self.closer(directory_fd)
                except OSError as exc:
                    raise PublicationVisibleButMetadataUncertain(
                        "publication is visible but directory-handle close is uncertain",
                        path=final_path,
                        original_error=exc,
                        file_content_durable=True,
                        publication_visible=True,
                        metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                    ) from exc

    def _publish_windows(self, temporary: Path, final_path: Path, mode: PublicationMode) -> None:
        if not _same_volume(temporary, final_path):
            raise SameVolumeRequired(
                "MoveFileExW publication requires a same-volume temporary file",
                path=final_path,
                file_content_durable=True,
            )
        flags = MOVEFILE_WRITE_THROUGH
        if mode is PublicationMode.REPLACE_EXISTING:
            flags |= MOVEFILE_REPLACE_EXISTING
        try:
            self.windows_move(temporary, final_path, flags)
        except PublicationApiUnavailable:
            raise
        except WindowsMoveFileError as exc:
            if mode is PublicationMode.CREATE_ONLY and exc.error_code in self._WINDOWS_CONFLICTS:
                raise PublicationConflict(
                    "create-only destination already exists",
                    path=final_path,
                    original_error=exc,
                    file_content_durable=True,
                ) from exc
            if exc.error_code in self._WINDOWS_UNSUPPORTED:
                raise PublicationApiUnavailable(
                    "MoveFileExW write-through publication is unsupported",
                    path=final_path,
                    original_error=exc,
                    file_content_durable=True,
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNSUPPORTED,
                ) from exc
            visible = not temporary.exists() and final_path.is_file()
            if visible:
                raise PublicationVisibleButMetadataUncertain(
                    "MoveFileExW failed after publication became visible",
                    path=final_path,
                    original_error=exc,
                    file_content_durable=True,
                    publication_visible=True,
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                ) from exc
            raise PublicationFailureBeforeVisibility(
                "MoveFileExW failed before publication visibility",
                path=final_path,
                original_error=exc,
                file_content_durable=True,
            ) from exc
        except OSError as exc:
            raise PublicationFailureBeforeVisibility(
                "MoveFileExW failed before publication visibility",
                path=final_path,
                original_error=exc,
                file_content_durable=True,
            ) from exc

    def publish(
        self,
        final_path: str | Path,
        data: bytes,
        *,
        mode: PublicationMode,
        replacement_authority: ReplacementAuthority | None = None,
    ) -> DurablePublicationResult:
        path = Path(final_path)
        parent = _canonical_parent(path)
        if not isinstance(data, bytes):
            raise TypeError("durable publication data must be bytes")
        if not isinstance(mode, PublicationMode):
            raise TypeError("durable publication mode must be typed")
        if mode is PublicationMode.REPLACE_EXISTING and replacement_authority not in {
            ReplacementAuthority.CAS_LOCK_HELD_AFTER_VALIDATION,
            ReplacementAuthority.CAPABILITY_PROBE,
        }:
            raise PublicationPathInvalid(
                "replacement requires typed lock/CAS or capability-probe authority", path=path
            )

        temporary: Path | None = None
        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=parent
            )
            temporary = Path(temporary_name)
        except OSError as exc:
            raise TemporaryFileCreateFailure(
                "temporary publication file could not be created", path=path, original_error=exc
            ) from exc

        handle: BinaryIO | None = None
        try:
            try:
                handle = os.fdopen(fd, "wb")
            except OSError as exc:
                try:
                    os.close(fd)
                except OSError:
                    pass
                self._fail_before_visibility(
                    TemporaryFileCreateFailure,
                    "temporary publication handle could not be opened",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                )
            try:
                self.writer(handle, data)
            except (OSError, ValueError) as exc:
                try:
                    handle.close()
                except OSError:
                    pass
                handle = None
                self._fail_before_visibility(
                    FileWriteFailure,
                    "complete file write failed",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                )
            try:
                self.flusher(handle)
            except (OSError, ValueError) as exc:
                try:
                    handle.close()
                except OSError:
                    pass
                handle = None
                self._fail_before_visibility(
                    FileFlushFailure,
                    "Python file-buffer flush failed",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                )
            try:
                self.file_sync(handle.fileno())
            except (OSError, ValueError) as exc:
                try:
                    handle.close()
                except OSError:
                    pass
                handle = None
                self._fail_before_visibility(
                    FileDurableFlushFailure,
                    "file-handle durable flush failed",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                )
            try:
                handle.close()
            except OSError as exc:
                handle = None
                self._fail_before_visibility(
                    FileFlushFailure,
                    "file close after durable flush failed",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                    file_content_durable=True,
                )
            handle = None

            try:
                published_temporary = temporary
                if self.platform_name == "nt":
                    self._publish_windows(temporary, path, mode)
                else:
                    self._publish_posix(temporary, path, mode)
                if published_temporary.exists():
                    cleanup_error = self._cleanup(published_temporary)
                    if cleanup_error is not None:
                        raise TemporaryCleanupFailure(
                            "successful publication left a temporary name that could not be removed",
                            path=path,
                            original_error=cleanup_error,
                            file_content_durable=True,
                            publication_visible=path.is_file(),
                            metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                        ) from cleanup_error
                    raise PostPublicationReloadFailure(
                        "publication primitive returned without consuming its temporary source",
                        path=path,
                        file_content_durable=True,
                        publication_visible=path.is_file(),
                        metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                    )
                temporary = None
            except PublicationConflict as exc:
                self._fail_before_visibility(
                    PublicationConflict,
                    str(exc),
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                    file_content_durable=True,
                )
            except (PublicationApiUnavailable, SameVolumeRequired, PublicationFailureBeforeVisibility) as exc:
                self._fail_before_visibility(
                    type(exc),
                    str(exc),
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                    file_content_durable=True,
                    metadata_status=exc.metadata_status,
                )
            except PublicationVisibleButMetadataUncertain as exc:
                if temporary.exists():
                    cleanup_error = self._cleanup(temporary)
                    if cleanup_error is not None:
                        raise TemporaryCleanupFailure(
                            "visible publication left an unremovable temporary name",
                            path=path,
                            original_error=cleanup_error,
                            file_content_durable=True,
                            publication_visible=True,
                            metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                        ) from exc
                temporary = None
                raise
            except FileExistsError as exc:
                self._fail_before_visibility(
                    PublicationConflict,
                    "create-only destination already exists",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                    file_content_durable=True,
                )
            except OSError as exc:
                visible = path.is_file() and not temporary.exists()
                if visible:
                    raise PublicationVisibleButMetadataUncertain(
                        "publication became visible but metadata durability is uncertain",
                        path=path,
                        original_error=exc,
                        file_content_durable=True,
                        publication_visible=True,
                        metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
                    ) from exc
                self._fail_before_visibility(
                    PublicationFailureBeforeVisibility,
                    "publication failed before visibility",
                    final_path=path,
                    temporary=temporary,
                    original_error=exc,
                    file_content_durable=True,
                )

            if temporary is not None or not path.is_file():
                raise PostPublicationReloadFailure(
                    "publication did not remove its temporary name or create the final file",
                    path=path,
                    file_content_durable=True,
                    publication_visible=path.is_file(),
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_DURABLE,
                )
            try:
                reloaded = path.read_bytes()
            except OSError as exc:
                raise PostPublicationReloadFailure(
                    "final publication cannot be reloaded",
                    path=path,
                    original_error=exc,
                    file_content_durable=True,
                    publication_visible=True,
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_DURABLE,
                ) from exc
            if reloaded != data:
                raise PostPublicationFingerprintMismatch(
                    "final publication bytes or fingerprint differ from intended bytes",
                    path=path,
                    file_content_durable=True,
                    publication_visible=True,
                    metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_DURABLE,
                )
            return DurablePublicationResult(
                platform=self.platform_name,
                profile_id=self.profile_id,
                mode=mode,
                final_path=str(path),
                byte_count=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                file_content=FileContentDurability.FILE_CONTENT_DURABLE,
                visibility=PublicationVisibility.PUBLICATION_VISIBLE,
                metadata=PublicationMetadataDurability.PUBLICATION_METADATA_DURABLE,
            )
        finally:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass


class CapabilityStep(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    CONFLICT_PRESERVED = "CONFLICT_PRESERVED"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class DurabilityCapabilityResult:
    platform: str
    profile_id: str
    filesystem_identity: Mapping[str, int | str]
    create_only_result: CapabilityStep
    replace_result: CapabilityStep
    cleanup_result: CapabilityStep
    reason_code: str
    detail: str

    @property
    def ready(self) -> bool:
        return (
            self.create_only_result is CapabilityStep.CONFLICT_PRESERVED
            and self.replace_result is CapabilityStep.SUCCEEDED
            and self.cleanup_result is CapabilityStep.SUCCEEDED
            and self.reason_code == "PLATFORM_DURABILITY_CAPABILITY_READY"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "profile_id": self.profile_id,
            "filesystem_identity": dict(self.filesystem_identity),
            "create_only_result": self.create_only_result.value,
            "replace_result": self.replace_result.value,
            "cleanup_result": self.cleanup_result.value,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "ready": self.ready,
        }


def _inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _cleanup_probe(root: Path, expected: frozenset[str]) -> bool:
    try:
        if not root.exists():
            return True
        metadata = os.lstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or _is_redirecting(root, metadata):
            return False
        children = tuple(root.iterdir())
        if any(child.name not in expected for child in children):
            return False
        for child in children:
            child_metadata = os.lstat(child)
            if not stat.S_ISREG(child_metadata.st_mode) or _is_redirecting(child, child_metadata):
                return False
        for child in children:
            child.unlink()
        root.rmdir()
        return not root.exists()
    except OSError:
        return False


def probe_platform_durability(
    *,
    parent: str | Path,
    source_root: str | Path,
    future_run_root: str | Path,
    adapter: PlatformDurabilityAdapter | None = None,
) -> DurabilityCapabilityResult:
    """Exercise the exact production adapter in one external disposable root."""

    selected = adapter or PlatformDurabilityAdapter()
    parent_path = Path(parent)
    source = Path(source_root)
    future = Path(future_run_root)
    create_status = CapabilityStep.NOT_RUN
    replace_status = CapabilityStep.NOT_RUN
    cleanup_status = CapabilityStep.NOT_RUN
    reason = "PLATFORM_DURABILITY_CAPABILITY_BLOCKED"
    detail = "durability capability probe did not complete"
    identity: dict[str, int | str] = {}
    probe_root: Path | None = None
    try:
        canonical_parent = _canonical_parent(parent_path / ".admissible-probe-anchor")
        if not source.is_absolute() or not future.is_absolute():
            raise PublicationPathInvalid("probe roots must be absolute", path=future)
        if future.exists():
            raise PublicationPathInvalid(
                "future run root must be fresh", path=future
            )
        identity = {
            "device": int(os.stat(canonical_parent).st_dev),
            "drive": os.path.splitdrive(os.fspath(canonical_parent))[0],
        }
        probe_root = Path(
            tempfile.mkdtemp(prefix=".admissible-durability-probe-", dir=canonical_parent)
        )
        root_metadata = os.lstat(probe_root)
        if not stat.S_ISDIR(root_metadata.st_mode) or _is_redirecting(probe_root, root_metadata):
            raise PublicationPathInvalid("capability probe root is redirecting", path=probe_root)
        if _inside(probe_root, source) or _inside(source, probe_root) or _inside(probe_root, future):
            raise PublicationPathInvalid("capability probe overlaps an authority root", path=probe_root)

        create_path = probe_root / "create-only.json"
        first = b'{"probe":"create-only-v1"}\n'
        selected.publish(create_path, first, mode=PublicationMode.CREATE_ONLY)
        if create_path.read_bytes() != first:
            raise PostPublicationFingerprintMismatch(
                "capability create-only bytes differ", path=create_path, publication_visible=True
            )
        try:
            selected.publish(create_path, b'{"probe":"must-not-overwrite"}\n', mode=PublicationMode.CREATE_ONLY)
        except PublicationConflict:
            if create_path.read_bytes() != first:
                raise PostPublicationFingerprintMismatch(
                    "create-only conflict changed original bytes", path=create_path, publication_visible=True
                )
            create_status = CapabilityStep.CONFLICT_PRESERVED
        else:
            raise PostPublicationFingerprintMismatch(
                "second create-only publication overwrote or accepted an existing destination",
                path=create_path,
                publication_visible=True,
            )

        replace_path = probe_root / "replace-existing.json"
        selected.publish(
            replace_path, b'{"probe":"replace-v1"}\n', mode=PublicationMode.CREATE_ONLY
        )
        replacement = b'{"probe":"replace-v2"}\n'
        selected.publish(
            replace_path,
            replacement,
            mode=PublicationMode.REPLACE_EXISTING,
            replacement_authority=ReplacementAuthority.CAPABILITY_PROBE,
        )
        if replace_path.read_bytes() != replacement:
            raise PostPublicationFingerprintMismatch(
                "capability replacement bytes differ", path=replace_path, publication_visible=True
            )
        replace_status = CapabilityStep.SUCCEEDED
        reason = "PLATFORM_DURABILITY_CAPABILITY_READY"
        detail = "create-only conflict preservation and authorized replacement both succeeded"
    except DurabilityAdapterError as exc:
        create_status = CapabilityStep.FAILED if create_status is CapabilityStep.NOT_RUN else create_status
        replace_status = CapabilityStep.FAILED if create_status is CapabilityStep.CONFLICT_PRESERVED else replace_status
        reason = exc.reason_code
        detail = str(exc)
    except OSError as exc:
        create_status = CapabilityStep.FAILED if create_status is CapabilityStep.NOT_RUN else create_status
        replace_status = CapabilityStep.FAILED if create_status is CapabilityStep.CONFLICT_PRESERVED else replace_status
        reason = "PLATFORM_DURABILITY_CAPABILITY_IO_FAILURE"
        detail = str(exc)
    finally:
        cleanup_status = (
            CapabilityStep.SUCCEEDED
            if probe_root is None or _cleanup_probe(probe_root, frozenset({"create-only.json", "replace-existing.json"}))
            else CapabilityStep.FAILED
        )
        if cleanup_status is CapabilityStep.FAILED:
            reason = "PLATFORM_DURABILITY_CAPABILITY_CLEANUP_FAILURE"
            detail = "capability probe cleanup could not be proven complete"
    return DurabilityCapabilityResult(
        selected.platform_name,
        selected.profile_id,
        identity,
        create_status,
        replace_status,
        cleanup_status,
        reason,
        detail,
    )


__all__ = [
    "CapabilityStep",
    "DurabilityAdapterError",
    "DurabilityCapabilityResult",
    "DurablePublicationResult",
    "FileContentDurability",
    "FileDurableFlushFailure",
    "FileFlushFailure",
    "FileWriteFailure",
    "MOVEFILE_REPLACE_EXISTING",
    "MOVEFILE_WRITE_THROUGH",
    "POSIX_FSYNC_PROFILE",
    "PlatformDurabilityAdapter",
    "PostPublicationFingerprintMismatch",
    "PostPublicationReloadFailure",
    "PublicationApiUnavailable",
    "PublicationConflict",
    "PublicationFailureBeforeVisibility",
    "PublicationMetadataDurability",
    "PublicationMode",
    "PublicationPathInvalid",
    "PublicationVisibility",
    "PublicationVisibleButMetadataUncertain",
    "ReplacementAuthority",
    "SameVolumeRequired",
    "TemporaryCleanupFailure",
    "TemporaryFileCreateFailure",
    "WINDOWS_MOVEFILEEX_PROFILE",
    "WindowsMoveFileError",
    "probe_platform_durability",
]
