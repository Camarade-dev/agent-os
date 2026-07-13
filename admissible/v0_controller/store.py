"""Locked CAS persistence with explicit pre-commit and post-replace outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import errno
import json
import os
from pathlib import Path
import tempfile
import time

from admissible.v0_controller.invariants import validate_state
from admissible.v0_controller.state import SessionState


class StoreError(RuntimeError):
    pass


class PreCommitFailure(StoreError):
    """A failure before replacement; the previous authoritative file remains valid."""

    def __init__(self, stage: str, message: str, original_error: BaseException | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.original_error = original_error


class SessionNotFound(StoreError):
    pass


class StaleRevisionError(StoreError):
    pass


class SchemaValidationError(PreCommitFailure):
    def __init__(self, message: str, original_error: BaseException | None = None) -> None:
        super().__init__("validation", message, original_error)


class LockAcquisitionError(StoreError):
    pass


class DurabilityError(PreCommitFailure):
    """Compatibility name for a typed pre-replace durability failure."""


class DirectoryDurabilityStatus(str, Enum):
    DURABLE = "durable"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class CommitResult:
    session_id: str
    committed_revision: int
    directory_durability: DirectoryDurabilityStatus


class CommittedButDurabilityUncertain(StoreError):
    """The replacement is visible, but directory durability could not be confirmed."""

    def __init__(
        self,
        *,
        committed_revision: int,
        session_id: str,
        visibility_confirmed: bool,
        original_durability_error: OSError,
    ) -> None:
        super().__init__(
            "V0 replacement committed but directory durability is uncertain "
            f"for {session_id} revision {committed_revision}"
        )
        self.committed_revision = committed_revision
        self.session_id = session_id
        self.visibility_confirmed = visibility_confirmed
        self.original_durability_error = original_durability_error


class _SessionFileLock:
    """An advisory OS lock whose release is owned by the operating system."""

    def __init__(self, path: Path, *, timeout: float) -> None:
        self.path = path
        self.timeout = timeout
        self._handle = None

    def _try_lock(self) -> None:
        assert self._handle is not None
        self._handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(self) -> None:
        assert self._handle is not None
        self._handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)

    def __enter__(self) -> "_SessionFileLock":
        try:
            self._handle = open(self.path, "a+b")
            self._handle.seek(0, os.SEEK_END)
            if self._handle.tell() == 0:
                self._handle.write(b"\0")
                self._handle.flush()
        except OSError as exc:
            raise LockAcquisitionError(f"cannot open V0 session lock {self.path.name}: {exc}") from exc

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._try_lock()
                return self
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    self._handle.close()
                    self._handle = None
                    raise LockAcquisitionError(f"timed out acquiring V0 session lock {self.path.name}") from exc
                time.sleep(0.01)

    def __exit__(self, exc_type, exc, traceback) -> None:
        unlock_error: OSError | None = None
        try:
            if self._handle is not None:
                try:
                    self._unlock()
                except OSError as error:
                    unlock_error = error
                self._handle.close()
        finally:
            self._handle = None
        if unlock_error is not None and exc_type is None:
            raise LockAcquisitionError(f"cannot release V0 session lock {self.path.name}: {unlock_error}")


class AtomicSessionStore:
    """One locked JSON file per V0 session with compare-and-swap replacement."""

    def __init__(self, directory: str | Path, *, lock_timeout: float = 5.0) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        self.lock_timeout = lock_timeout
        self.last_directory_fsync_status = "not_attempted"

    def _path(self, session_id: str) -> Path:
        if not session_id or any(char in session_id for char in "\\/\x00"):
            raise StoreError("invalid session id")
        return self.directory / f"{session_id}.v0.json"

    @staticmethod
    def _serialize(state: SessionState) -> bytes:
        return state.canonical_bytes() + b"\n"

    def _lock_for(self, path: Path) -> _SessionFileLock:
        return _SessionFileLock(path.with_name(f".{path.name}.lock"), timeout=self.lock_timeout)

    def _read_validated(self, path: Path, session_id: str) -> SessionState:
        if not path.exists():
            raise SessionNotFound(session_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("session root must be an object")
            state = SessionState.from_dict(raw)
            validate_state(state)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SchemaValidationError(f"invalid V0 session {session_id}: {exc}", exc) from exc
        if state.session_id != session_id:
            raise SchemaValidationError("V0 session id does not match storage filename")
        return state

    @staticmethod
    def _directory_fsync_is_unsupported(exc: OSError) -> bool:
        unsupported = {errno.EINVAL, errno.ENOTSUP}
        if hasattr(errno, "EOPNOTSUPP"):
            unsupported.add(errno.EOPNOTSUPP)
        if os.name == "nt":
            unsupported.update({errno.EACCES, errno.EPERM})
        return exc.errno in unsupported

    def _fsync_directory(self) -> DirectoryDurabilityStatus:
        try:
            directory_fd = os.open(str(self.directory), os.O_RDONLY)
        except OSError as exc:
            if self._directory_fsync_is_unsupported(exc):
                self.last_directory_fsync_status = DirectoryDurabilityStatus.UNSUPPORTED.value
                return DirectoryDurabilityStatus.UNSUPPORTED
            raise
        try:
            os.fsync(directory_fd)
            self.last_directory_fsync_status = DirectoryDurabilityStatus.DURABLE.value
            return DirectoryDurabilityStatus.DURABLE
        except OSError as exc:
            if self._directory_fsync_is_unsupported(exc):
                self.last_directory_fsync_status = DirectoryDurabilityStatus.UNSUPPORTED.value
                return DirectoryDurabilityStatus.UNSUPPORTED
            raise
        finally:
            os.close(directory_fd)

    def _write_temp_file(self, path: Path, data: bytes) -> str:
        temp_name: str | None = None
        written = False
        try:
            fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=self.directory)
        except OSError as exc:
            raise DurabilityError("temp_create", f"cannot create V0 session temporary file: {exc}", exc) from exc
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError as exc:
                    raise DurabilityError("file_fsync", f"V0 session temporary-file fsync failed: {exc}", exc) from exc
            written = True
            return temp_name
        except DurabilityError:
            raise
        except OSError as exc:
            raise DurabilityError("temp_write", f"V0 session temporary-file write failed: {exc}", exc) from exc
        finally:
            # The successful caller owns the returned path.  Any failed temp
            # write is cleaned best-effort without replacing the old session.
            if not written and temp_name is not None and os.path.exists(temp_name):
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

    def _visible_as_intended(self, path: Path, state: SessionState) -> bool:
        try:
            visible = self._read_validated(path, state.session_id)
        except StoreError:
            return False
        return visible.revision == state.revision and visible.canonical_bytes() == state.canonical_bytes()

    def _atomic_write(self, path: Path, state: SessionState) -> CommitResult:
        """Write once; replacement failures are pre-commit, directory failure is not."""

        temp_name = self._write_temp_file(path, self._serialize(state))
        try:
            try:
                os.replace(temp_name, path)
            except OSError as exc:
                raise DurabilityError("replace", f"V0 session atomic replace failed: {exc}", exc) from exc
            temp_name = None  # replacement succeeded: this revision is logically committed
            try:
                directory_durability = self._fsync_directory()
            except OSError as exc:
                self.last_directory_fsync_status = "uncertain"
                raise CommittedButDurabilityUncertain(
                    committed_revision=state.revision,
                    session_id=state.session_id,
                    visibility_confirmed=self._visible_as_intended(path, state),
                    original_durability_error=exc,
                ) from exc
            return CommitResult(
                session_id=state.session_id,
                committed_revision=state.revision,
                directory_durability=directory_durability,
            )
        finally:
            if temp_name is not None and os.path.exists(temp_name):
                try:
                    os.unlink(temp_name)
                except OSError:
                    # The old session remains readable and the temp artifact is
                    # not authoritative.  Do not mask the typed save outcome.
                    pass

    def create(self, state: SessionState) -> CommitResult:
        """Persist exactly one fully-created V0 session; never overwrite it."""

        if state.revision != 0:
            raise SchemaValidationError("new V0 sessions must begin at revision zero")
        path = self._path(state.session_id)
        with self._lock_for(path):
            try:
                validate_state(state)
            except ValueError as exc:
                raise SchemaValidationError(str(exc), exc) from exc
            if path.exists():
                raise PreCommitFailure("create", "V0 session already exists")
            return self._atomic_write(path, state)

    def load(self, session_id: str) -> SessionState:
        return self._read_validated(self._path(session_id), session_id)

    def replace(self, state: SessionState, *, expected_revision: int) -> CommitResult:
        """Lock read/validate/CAS/write/replace as one critical section."""

        path = self._path(state.session_id)
        with self._lock_for(path):
            if state.revision != expected_revision + 1:
                raise PreCommitFailure("revision", "persisted tick must advance revision exactly once")
            try:
                validate_state(state)
            except ValueError as exc:
                raise SchemaValidationError(str(exc), exc) from exc
            current = self._read_validated(path, state.session_id)
            if current.revision != expected_revision:
                raise StaleRevisionError(f"expected revision {expected_revision}, found {current.revision}")
            return self._atomic_write(path, state)
