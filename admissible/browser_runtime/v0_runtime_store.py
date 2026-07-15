"""Durable single-attempt store for V0 runtime verification results (Slice 5A).

Exactly one runtime verification result may ever be attached to a persisted V0
run. This store enforces that structurally: :meth:`attach` writes the typed
result plus its durable evidence artifacts (screenshot, serialized DOM) once,
under a lock, and refuses to overwrite an existing attachment. Reconstruction
(:meth:`load`) returns the byte-identical result, so a persisted verdict is
stable across process restarts.

The result is stored *alongside* the persisted run as an immutable sidecar. It
never mutates the V0 :class:`~admissible.v0_controller.state.SessionState`
itself: the original execution, structural evidence, and runtime evidence all
remain independently immutable.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admissible.browser_runtime.v0_runtime_verification import (
    RuntimeVerificationRun,
    V0RuntimeVerificationResult,
)


class RuntimeStoreError(RuntimeError):
    pass


class RuntimeAttemptExists(RuntimeStoreError):
    """A runtime verification result is already attached; a second is refused."""


class RuntimeAttemptNotFound(RuntimeStoreError):
    pass


@dataclass(frozen=True)
class RuntimeArtifact:
    relative_path: str
    sha256: str
    byte_count: int

    def to_dict(self) -> dict[str, Any]:
        return {"relative_path": self.relative_path, "sha256": self.sha256, "byte_count": self.byte_count}


@dataclass(frozen=True)
class RuntimeAttachment:
    result: V0RuntimeVerificationResult
    artifacts: tuple[RuntimeArtifact, ...]
    directory: Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _DirLock:
    """A minimal advisory lock on a sidecar lock file (portable, non-blocking retry)."""

    def __init__(self, path: Path, *, timeout: float) -> None:
        self.path = path
        self.timeout = timeout
        self._handle = None

    def __enter__(self) -> "_DirLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    self._handle.seek(0)
                    msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if time.monotonic() >= deadline:
                    self._handle.close()
                    self._handle = None
                    raise RuntimeStoreError(f"timed out acquiring runtime lock {self.path.name}") from exc
                time.sleep(0.01)

    def __exit__(self, *exc: Any) -> None:
        if self._handle is not None:
            try:
                if os.name == "nt":
                    import msvcrt

                    self._handle.seek(0)
                    msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._handle.close()
                self._handle = None


class V0RuntimeVerificationStore:
    """One immutable runtime-verification attachment per session, write-once."""

    def __init__(self, directory: str | Path, *, lock_timeout: float = 5.0) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock_timeout = lock_timeout

    def _validate_session_id(self, session_id: str) -> str:
        if not session_id or any(ch in session_id for ch in "\\/\x00"):
            raise RuntimeStoreError("invalid session id")
        return session_id

    def _result_path(self, session_id: str) -> Path:
        return self.directory / f"{self._validate_session_id(session_id)}.runtime.json"

    def _artifacts_dir(self, session_id: str) -> Path:
        return self.directory / f"{self._validate_session_id(session_id)}.runtime.d"

    def _lock(self, session_id: str) -> _DirLock:
        # The advisory lock is machine-local control state, never canonical
        # evidence: it lives under a temporary control directory *outside* the
        # store (and therefore outside any committed evidence archive). Its
        # identity is derived deterministically from the absolute store path and
        # session id, so exactly one writer per (store, session) is still
        # serialized without ever placing a lock file inside the archive.
        self._validate_session_id(session_id)
        key = hashlib.sha256(
            f"{self.directory.resolve().as_posix()}\x00{session_id}".encode("utf-8")
        ).hexdigest()
        lock_dir = Path(tempfile.gettempdir()) / "admissible-v0-runtime-locks"
        return _DirLock(lock_dir / f"{key}.runtime.lock", timeout=self.lock_timeout)

    def has_attachment(self, session_id: str) -> bool:
        return self._result_path(session_id).is_file()

    def _atomic_write(self, path: Path, data: bytes) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
            temp_name = None
        finally:
            if temp_name is not None and os.path.exists(temp_name):
                os.unlink(temp_name)

    def attach(self, run: RuntimeVerificationRun) -> RuntimeAttachment:
        """Persist exactly one runtime verification result; never overwrite it."""

        result = run.result
        session_id = result.session_id
        result_path = self._result_path(session_id)
        with self._lock(session_id):
            if result_path.exists():
                raise RuntimeAttemptExists(
                    f"a runtime verification result is already attached to session {session_id!r}"
                )
            artifacts_dir = self._artifacts_dir(session_id)
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            artifacts: list[RuntimeArtifact] = []

            if run.screenshot_blob is not None and result.screenshot_sha256:
                name = "screenshot.png"
                self._atomic_write(artifacts_dir / name, run.screenshot_blob)
                artifacts.append(
                    RuntimeArtifact(name, _sha256(run.screenshot_blob), len(run.screenshot_blob))
                )
            if run.dom_document_bytes is not None and result.dom_document_sha256:
                name = "document.html"
                self._atomic_write(artifacts_dir / name, run.dom_document_bytes)
                artifacts.append(
                    RuntimeArtifact(name, _sha256(run.dom_document_bytes), len(run.dom_document_bytes))
                )

            payload = {
                "result": result.to_dict(),
                "artifacts": [a.to_dict() for a in artifacts],
            }
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            self._atomic_write(result_path, body)
            return RuntimeAttachment(result=result, artifacts=tuple(artifacts), directory=artifacts_dir)

    def load(self, session_id: str) -> RuntimeAttachment:
        result_path = self._result_path(session_id)
        if not result_path.is_file():
            raise RuntimeAttemptNotFound(session_id)
        raw = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "result" not in raw:
            raise RuntimeStoreError(f"corrupt runtime attachment for {session_id!r}")
        result = V0RuntimeVerificationResult.from_dict(raw["result"])
        artifacts = tuple(
            RuntimeArtifact(a["relative_path"], a["sha256"], a["byte_count"]) for a in raw.get("artifacts") or []
        )
        return RuntimeAttachment(result=result, artifacts=artifacts, directory=self._artifacts_dir(session_id))

    def verify_artifacts(self, session_id: str) -> bool:
        """True iff every persisted artifact still hashes to its recorded digest."""

        attachment = self.load(session_id)
        for artifact in attachment.artifacts:
            path = attachment.directory / artifact.relative_path
            if not path.is_file():
                return False
            if _sha256(path.read_bytes()) != artifact.sha256:
                return False
        return True
