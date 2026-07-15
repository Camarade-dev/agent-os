"""Durable, write-once store for a single operator terminal disposition (Slice 5B).

Exactly one human disposition (``ACCEPT_RESULT`` / ``REJECT_RESULT``) may ever be
attached to a persisted V0 run. This store enforces that structurally:

* the record is written **atomically** (temp file + ``os.replace``) under an
  advisory **lock**, so a partially written record can never be observed;
* it is **write-once**: an identical repeated request is **idempotent** (returns
  the existing record); a *contradictory* request (different disposition, note,
  or evidence fingerprints) is **refused**;
* it is **reconstructible after restart**: :meth:`load` returns the byte-stable
  record;
* it **fails closed**: a malformed or tampered record raises rather than being
  interpreted, and a self-fingerprint over the canonical body detects tampering.

The disposition lives **outside** the immutable evidence archive (in its own
review directory), so recording a disposition never mutates the session, the
runtime result, or any evidence artifact, and never disturbs the umbrella
archive manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "admissible_v0_review_disposition_v1"

ACCEPT_RESULT = "ACCEPT_RESULT"
REJECT_RESULT = "REJECT_RESULT"
_VALID_DISPOSITIONS = frozenset({ACCEPT_RESULT, REJECT_RESULT})

# Bounded operator note length (defensive; keeps the sidecar small and local).
MAX_NOTE_LENGTH = 2000

DEFAULT_OPERATOR_CLASSIFICATION = "local_single_user_v0_operator"


class DispositionStoreError(RuntimeError):
    pass


class DispositionConflict(DispositionStoreError):
    """A contradictory second disposition was refused."""


class DispositionCorrupt(DispositionStoreError):
    """A persisted disposition failed its structural/integrity checks (fail closed)."""


def _fingerprint(payload: dict[str, Any]) -> str:
    """Deterministic self-fingerprint over the canonical disposition body."""

    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DispositionRecord:
    schema_version: str
    session_id: str
    disposition: str
    note: str
    operator_classification: str
    timestamp: str
    disposition_nonce: str
    evidence_fingerprints: dict[str, str]
    record_fingerprint: str

    # Fields that define semantic equality of a disposition *request*. Two
    # requests are "the same" (idempotent) iff these all agree.
    def _semantic_key(self) -> tuple[Any, ...]:
        return (
            self.session_id,
            self.disposition,
            self.note,
            self.operator_classification,
            tuple(sorted(self.evidence_fingerprints.items())),
        )

    def is_same_request(self, other: "DispositionRecord") -> bool:
        return self._semantic_key() == other._semantic_key()

    def _body_for_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "disposition": self.disposition,
            "note": self.note,
            "operator_classification": self.operator_classification,
            "timestamp": self.timestamp,
            "disposition_nonce": self.disposition_nonce,
            "evidence_fingerprints": dict(self.evidence_fingerprints),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self._body_for_fingerprint()
        data["record_fingerprint"] = self.record_fingerprint
        return data

    @classmethod
    def from_dict(cls, raw: Any) -> "DispositionRecord":
        if not isinstance(raw, dict):
            raise DispositionCorrupt("disposition is not an object")
        try:
            schema_version = str(raw["schema_version"])
            session_id = str(raw["session_id"])
            disposition = str(raw["disposition"])
            note = str(raw.get("note", ""))
            operator_classification = str(raw["operator_classification"])
            timestamp = str(raw["timestamp"])
            disposition_nonce = str(raw["disposition_nonce"])
            fingerprints = raw["evidence_fingerprints"]
            record_fingerprint = str(raw["record_fingerprint"])
        except (KeyError, TypeError) as exc:
            raise DispositionCorrupt(f"missing/invalid disposition field: {exc}") from exc

        if schema_version != SCHEMA_VERSION:
            raise DispositionCorrupt(f"unexpected schema version {schema_version!r}")
        if disposition not in _VALID_DISPOSITIONS:
            raise DispositionCorrupt(f"invalid disposition {disposition!r}")
        if not isinstance(fingerprints, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in fingerprints.items()
        ):
            raise DispositionCorrupt("invalid evidence_fingerprints")
        if len(note) > MAX_NOTE_LENGTH:
            raise DispositionCorrupt("note exceeds bound")

        record = cls(
            schema_version=schema_version,
            session_id=session_id,
            disposition=disposition,
            note=note,
            operator_classification=operator_classification,
            timestamp=timestamp,
            disposition_nonce=disposition_nonce,
            evidence_fingerprints=dict(fingerprints),
            record_fingerprint=record_fingerprint,
        )
        expected = _fingerprint(record._body_for_fingerprint())
        if expected != record_fingerprint:
            raise DispositionCorrupt("record fingerprint mismatch (tampered)")
        return record


class _FileLock:
    """Minimal cross-platform advisory lock (non-blocking retry until timeout)."""

    def __init__(self, path: Path, *, timeout: float) -> None:
        self.path = path
        self.timeout = timeout
        self._handle = None

    def __enter__(self) -> "_FileLock":
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
                    raise DispositionStoreError(
                        f"timed out acquiring disposition lock {self.path.name}"
                    ) from exc
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


class ReviewDispositionStore:
    """One immutable operator disposition per session, write-once and lock-protected."""

    def __init__(self, directory: str | Path, *, lock_timeout: float = 5.0) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock_timeout = lock_timeout

    def _validate_session_id(self, session_id: str) -> str:
        if not session_id or any(ch in session_id for ch in "\\/\x00"):
            raise DispositionStoreError("invalid session id")
        return session_id

    def _record_path(self, session_id: str) -> Path:
        return self.directory / f"{self._validate_session_id(session_id)}.disposition.json"

    def _lock_path(self, session_id: str) -> Path:
        return self.directory / f".{self._validate_session_id(session_id)}.disposition.lock"

    def has_disposition(self, session_id: str) -> bool:
        return self._record_path(session_id).is_file()

    def load(self, session_id: str) -> DispositionRecord | None:
        path = self._record_path(session_id)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise DispositionCorrupt(f"unreadable disposition: {exc}") from exc
        return DispositionRecord.from_dict(raw)

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

    def record(
        self,
        *,
        session_id: str,
        disposition: str,
        evidence_fingerprints: dict[str, str],
        note: str = "",
        operator_classification: str = DEFAULT_OPERATOR_CLASSIFICATION,
        timestamp: str | None = None,
        nonce: str | None = None,
    ) -> DispositionRecord:
        """Persist exactly one disposition. Idempotent for an identical request;
        a contradictory request raises :class:`DispositionConflict`.
        """

        self._validate_session_id(session_id)
        if disposition not in _VALID_DISPOSITIONS:
            raise DispositionStoreError(f"invalid disposition {disposition!r}")
        if note is None:
            note = ""
        if len(note) > MAX_NOTE_LENGTH:
            raise DispositionStoreError("note exceeds bound")
        if not isinstance(evidence_fingerprints, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in evidence_fingerprints.items()
        ):
            raise DispositionStoreError("invalid evidence_fingerprints")

        record_path = self._record_path(session_id)
        with _FileLock(self._lock_path(session_id), timeout=self.lock_timeout):
            existing = self.load(session_id)

            if existing is not None:
                # Compare the *request semantics* (ignoring minted identity).
                candidate_key = (
                    session_id,
                    disposition,
                    note,
                    operator_classification,
                    tuple(sorted(evidence_fingerprints.items())),
                )
                if candidate_key != existing._semantic_key():
                    raise DispositionConflict(
                        f"a contradictory disposition already exists for session {session_id!r}"
                    )
                # Identical request -> idempotent: return the stored record as-is.
                return existing

            # Fresh identity for a brand-new disposition.
            body = {
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id,
                "disposition": disposition,
                "note": note,
                "operator_classification": operator_classification,
                "timestamp": timestamp or _utc_now(),
                "disposition_nonce": nonce or uuid.uuid4().hex,
                "evidence_fingerprints": dict(evidence_fingerprints),
            }
            body["record_fingerprint"] = _fingerprint(body)
            data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            self._atomic_write(record_path, data)
            return DispositionRecord.from_dict(json.loads(data.decode("utf-8")))


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
