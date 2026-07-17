"""Sibling atomic CAS store for delegated-gate state (independent of V0 types)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time

from admissible.delegated_gate.durability import (
    DurabilityAdapterError,
    PlatformDurabilityAdapter,
    PostPublicationReloadFailure,
    PublicationConflict,
    PublicationMode,
    PublicationVisibleButMetadataUncertain,
    ReplacementAuthority,
)
from admissible.delegated_gate.invariants import validate_state
from admissible.delegated_gate.state import DelegatedSessionState, Phase


class DelegatedGateStoreError(RuntimeError):
    pass


class SessionNotFound(DelegatedGateStoreError):
    pass


class SessionAlreadyExists(DelegatedGateStoreError):
    pass


class StaleRevisionError(DelegatedGateStoreError):
    pass


class PersistedStateInvalid(DelegatedGateStoreError):
    pass


class LockAcquisitionError(DelegatedGateStoreError):
    pass


class DurabilityError(DelegatedGateStoreError):
    pass


class InvalidSuccessorError(DelegatedGateStoreError):
    pass


class CommittedButDurabilityUncertain(DelegatedGateStoreError):
    """Atomic replacement is visible but directory durability was not proven."""

    def __init__(
        self,
        *,
        session_id: str,
        committed_revision: int,
        visibility_confirmed: bool,
        original_error: BaseException,
    ) -> None:
        super().__init__(
            "delegated session replacement committed but directory durability is uncertain"
        )
        self.session_id = session_id
        self.committed_revision = committed_revision
        self.visibility_confirmed = visibility_confirmed
        self.original_error = original_error


class _FileLock:
    def __init__(self, path: Path, *, timeout: float) -> None:
        self.path = path
        self.timeout = timeout
        self._handle = None

    def __enter__(self) -> "_FileLock":
        try:
            self._handle = open(self.path, "a+b")
            self._handle.seek(0, os.SEEK_END)
            if self._handle.tell() == 0:
                self._handle.write(b"\0")
                self._handle.flush()
        except OSError as exc:
            raise LockAcquisitionError(f"cannot open delegated session lock: {exc}") from exc
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if time.monotonic() >= deadline:
                    self._handle.close()
                    self._handle = None
                    raise LockAcquisitionError("timed out acquiring delegated session lock") from exc
                time.sleep(0.01)

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._handle is None:
            return
        try:
            self._handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


class AtomicDelegatedSessionStore:
    """One validated JSON authority file per session with locked CAS replacement."""

    def __init__(
        self,
        directory: str | Path,
        *,
        lock_timeout: float = 5.0,
        durability_adapter: PlatformDurabilityAdapter | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        self.lock_timeout = lock_timeout
        self.durability_adapter = durability_adapter or PlatformDurabilityAdapter()

    def _path(self, session_id: str) -> Path:
        if (
            not isinstance(session_id, str)
            or not session_id
            or any(char in session_id for char in "\\/\x00")
        ):
            raise DelegatedGateStoreError("invalid session ID")
        return self.directory / f"{session_id}.delegated-gate.json"

    def _lock(self, path: Path) -> _FileLock:
        return _FileLock(path.with_name(f".{path.name}.lock"), timeout=self.lock_timeout)

    @staticmethod
    def _serialized(state: DelegatedSessionState) -> bytes:
        return state.canonical_bytes() + b"\n"

    def _read_validated(self, path: Path, session_id: str) -> DelegatedSessionState:
        if not path.is_file():
            raise SessionNotFound(session_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("session root must be an object")
            state = DelegatedSessionState.from_dict(raw)
            validate_state(state)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PersistedStateInvalid(f"invalid delegated session {session_id}: {exc}") from exc
        if state.session_id != session_id:
            raise PersistedStateInvalid("persisted session ID differs from its filename")
        return state

    def _durable_publish(
        self,
        path: Path,
        state: DelegatedSessionState,
        *,
        mode: PublicationMode,
    ) -> None:
        try:
            self.durability_adapter.publish(
                path,
                self._serialized(state),
                mode=mode,
                replacement_authority=(
                    ReplacementAuthority.CAS_LOCK_HELD_AFTER_VALIDATION
                    if mode is PublicationMode.REPLACE_EXISTING
                    else None
                ),
            )
        except PublicationConflict as exc:
            raise SessionAlreadyExists(state.session_id) from exc
        except PublicationVisibleButMetadataUncertain as exc:
            try:
                visible = self._read_validated(path, state.session_id)
                visibility_confirmed = visible.canonical_bytes() == state.canonical_bytes()
            except DelegatedGateStoreError:
                visibility_confirmed = False
            raise CommittedButDurabilityUncertain(
                session_id=state.session_id,
                committed_revision=state.revision,
                visibility_confirmed=visibility_confirmed,
                original_error=exc,
            ) from exc
        except PostPublicationReloadFailure as exc:
            raise PersistedStateInvalid(
                f"{exc.reason_code}: delegated state publication cannot be reloaded exactly"
            ) from exc
        except DurabilityAdapterError as exc:
            raise DurabilityError(f"{exc.reason_code}: {exc}") from exc
        # Persistence is authoritative only after the production state parser
        # reconstructs every invariant and the canonical object is exact.
        reconstructed = self._read_validated(path, state.session_id)
        if reconstructed.canonical_bytes() != state.canonical_bytes():
            raise PersistedStateInvalid("post-publication reconstruction differs from intended state")

    def create(self, state: DelegatedSessionState) -> None:
        if state.revision != 0:
            raise PersistedStateInvalid("new delegated sessions must start at revision zero")
        path = self._path(state.session_id)
        with self._lock(path):
            try:
                validate_state(state)
            except ValueError as exc:
                raise PersistedStateInvalid(str(exc)) from exc
            if path.exists():
                raise SessionAlreadyExists(state.session_id)
            self._durable_publish(path, state, mode=PublicationMode.CREATE_ONLY)

    def load(self, session_id: str) -> DelegatedSessionState:
        return self._read_validated(self._path(session_id), session_id)

    @staticmethod
    def _validate_successor(
        current: DelegatedSessionState,
        successor: DelegatedSessionState,
    ) -> None:
        if current.mission != successor.mission or current.gate_plan != successor.gate_plan:
            raise InvalidSuccessorError("mission and gate plan are immutable after creation")
        if successor.checkpoint_history[: len(current.checkpoint_history)] != current.checkpoint_history:
            raise InvalidSuccessorError("checkpoint history is append-only")
        if successor.audit_history[: len(current.audit_history)] != current.audit_history:
            raise InvalidSuccessorError("audit history is append-only")
        if len(successor.checkpoint_history) - len(current.checkpoint_history) not in {0, 1}:
            raise InvalidSuccessorError("one transition may append at most one checkpoint")
        if len(successor.audit_history) - len(current.audit_history) not in {0, 1}:
            raise InvalidSuccessorError("one transition may append at most one verdict")
        allowed_phases = {
            Phase.READY_FOR_GATE: {Phase.GATE_EXECUTING},
            Phase.GATE_EXECUTING: {Phase.CHECKPOINT_CAPTURED},
            Phase.CHECKPOINT_CAPTURED: {Phase.AUDITING, Phase.REAUDITING},
            Phase.AUDITING: {
                Phase.GATE_PASSED,
                Phase.REPAIR_AUTHORIZED,
                Phase.AWAITING_HUMAN,
            },
            Phase.REPAIR_AUTHORIZED: {Phase.REPAIR_EXECUTING},
            Phase.REPAIR_EXECUTING: {Phase.CHECKPOINT_CAPTURED},
            Phase.REAUDITING: {Phase.GATE_PASSED, Phase.AWAITING_HUMAN},
            Phase.GATE_PASSED: {Phase.READY_FOR_GATE, Phase.AWAITING_HUMAN},
            Phase.AWAITING_HUMAN: {Phase.COMPLETED},
            Phase.COMPLETED: set(),
        }
        if successor.phase not in allowed_phases[current.phase]:
            raise InvalidSuccessorError(
                f"{successor.phase.value} is not a legal one-step successor of {current.phase.value}"
            )
        expected_gate_index = current.current_gate_index
        if current.phase == Phase.GATE_PASSED and successor.phase == Phase.READY_FOR_GATE:
            expected_gate_index += 1
        if successor.current_gate_index != expected_gate_index:
            raise InvalidSuccessorError("current gate index changed outside predefined advancement")

    def replace(self, state: DelegatedSessionState, *, expected_revision: int) -> None:
        path = self._path(state.session_id)
        with self._lock(path):
            if state.revision != expected_revision + 1:
                raise StaleRevisionError("replacement must advance revision exactly once")
            try:
                validate_state(state)
            except ValueError as exc:
                raise PersistedStateInvalid(str(exc)) from exc
            current = self._read_validated(path, state.session_id)
            if current.revision != expected_revision:
                raise StaleRevisionError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )
            self._validate_successor(current, state)
            self._durable_publish(path, state, mode=PublicationMode.REPLACE_EXISTING)
