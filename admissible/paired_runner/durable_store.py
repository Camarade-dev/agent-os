"""One canonical durable publication primitive for immutable M2 objects.

Every persisted paired-runner object goes through :meth:`DurableObjectStore.publish`.
The primitive is deliberately narrow: it serializes through the Milestone 1
canonical representation, creates the object with no-replace semantics, and
never overwrites a different existing object.

The durability contract is exactly the one recorded in
``implementation/M2_PLATFORM_AND_DURABILITY_CONTRACT.md``: Linux POSIX
semantics with CPython's standard library.  Nothing here claims durability
beyond what ``fsync`` on the selected platform provides.

Fault injection points are named constants.  The default injector is inert;
only a test may supply one that raises.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
from typing import Any, Callable, Iterable

from .canonical import (
    CanonicalizationError,
    Fingerprint,
    canonical_bytes,
    fingerprint_bytes,
    parse_canonical_json,
)
from .observation import PublicationReceipt


# --- Fault injection ---------------------------------------------------------

#: Publication stages.  A publication-internal fault point is the stage name
#: joined to the exact durability phase inside :meth:`DurableObjectStore.publish`.
STAGE_PROPOSAL_PUBLICATION = "PROPOSAL_PUBLICATION"
STAGE_TERMINAL_RECEIPT_PUBLICATION = "TERMINAL_RECEIPT_PUBLICATION"
STAGE_RECONCILIATION_PUBLICATION = "RECONCILIATION_PUBLICATION"

FAULT_BEFORE_PROPOSAL_PUBLICATION = "BEFORE_PROPOSAL_PUBLICATION"
FAULT_DURING_PROPOSAL_TEMP_WRITE = f"{STAGE_PROPOSAL_PUBLICATION}:TEMP_WRITE"
FAULT_AFTER_PROPOSAL_FSYNC_BEFORE_RENAME = f"{STAGE_PROPOSAL_PUBLICATION}:AFTER_FILE_FSYNC_BEFORE_COMMIT"
FAULT_AFTER_PROPOSAL_RENAME_BEFORE_DIR_FSYNC = f"{STAGE_PROPOSAL_PUBLICATION}:AFTER_COMMIT_BEFORE_DIRECTORY_FSYNC"
FAULT_AFTER_PROPOSAL_PUBLICATION = "AFTER_PROPOSAL_PUBLICATION"
FAULT_BEFORE_RESERVATION_PUBLICATION = "BEFORE_RESERVATION_PUBLICATION"
FAULT_AFTER_RESERVATION_PUBLICATION = "AFTER_RESERVATION_PUBLICATION"
FAULT_BEFORE_STARTED_PUBLICATION = "BEFORE_STARTED_PUBLICATION"
FAULT_AFTER_STARTED_BEFORE_EFFECT = "AFTER_STARTED_BEFORE_EFFECT"
FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT = "AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT"
FAULT_DURING_TERMINAL_RECEIPT_PUBLICATION = f"{STAGE_TERMINAL_RECEIPT_PUBLICATION}:TEMP_WRITE"
FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION = "AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION"
FAULT_DURING_RECONCILIATION_PUBLICATION = f"{STAGE_RECONCILIATION_PUBLICATION}:TEMP_WRITE"

FAULT_POINTS: tuple[str, ...] = (
    FAULT_BEFORE_PROPOSAL_PUBLICATION,
    FAULT_DURING_PROPOSAL_TEMP_WRITE,
    FAULT_AFTER_PROPOSAL_FSYNC_BEFORE_RENAME,
    FAULT_AFTER_PROPOSAL_RENAME_BEFORE_DIR_FSYNC,
    FAULT_AFTER_PROPOSAL_PUBLICATION,
    FAULT_BEFORE_RESERVATION_PUBLICATION,
    FAULT_AFTER_RESERVATION_PUBLICATION,
    FAULT_BEFORE_STARTED_PUBLICATION,
    FAULT_AFTER_STARTED_BEFORE_EFFECT,
    FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT,
    FAULT_DURING_TERMINAL_RECEIPT_PUBLICATION,
    FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION,
    FAULT_DURING_RECONCILIATION_PUBLICATION,
)

# The publication-internal points are parameterised by the object kind, so a
# crash "during the proposal temporary write" is expressed as the generic
# publication phase applied to the proposal object.
PUBLICATION_PHASE_TEMP_WRITE = "TEMP_WRITE"
PUBLICATION_PHASE_AFTER_FILE_FSYNC = "AFTER_FILE_FSYNC_BEFORE_COMMIT"
PUBLICATION_PHASE_AFTER_COMMIT_BEFORE_DIR_FSYNC = "AFTER_COMMIT_BEFORE_DIRECTORY_FSYNC"
PUBLICATION_PHASE_AFTER_COMMIT = "AFTER_DIRECTORY_FSYNC"
PUBLICATION_PHASES = (
    PUBLICATION_PHASE_TEMP_WRITE,
    PUBLICATION_PHASE_AFTER_FILE_FSYNC,
    PUBLICATION_PHASE_AFTER_COMMIT_BEFORE_DIR_FSYNC,
    PUBLICATION_PHASE_AFTER_COMMIT,
)


class InjectedFault(BaseException):
    """A deterministic simulated crash.

    It derives from :class:`BaseException` so that ordinary ``except Exception``
    error handling inside the substrate cannot accidentally swallow a simulated
    crash and turn it into a normal, recoverable outcome.
    """

    def __init__(self, point: str) -> None:
        super().__init__(f"injected fault at {point}")
        self.point = point


class FaultInjector:
    """Test-only deterministic fault source.  Inert unless points are armed."""

    def __init__(self, armed: Iterable[str] = ()) -> None:
        self._armed = set(armed)
        self.observed: list[str] = []

    def arm(self, point: str) -> None:
        self._armed.add(point)

    def check(self, point: str) -> None:
        self.observed.append(point)
        if point in self._armed:
            raise InjectedFault(point)


class _InertInjector(FaultInjector):
    """The production default: it records nothing and never raises."""

    def __init__(self) -> None:
        super().__init__(())

    def check(self, point: str) -> None:  # pragma: no cover - trivially inert
        return None


NULL_FAULT_INJECTOR = _InertInjector()


# --- Durable publication -----------------------------------------------------

class PublicationConflict(RuntimeError):
    """A different object already occupies this immutable identity."""


class CorruptDurableObject(RuntimeError):
    """A committed object could not be reconstructed from its bytes."""


DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
TEMPORARY_PREFIX = ".tmp-publication-"
IDEMPOTENCY_RULE = (
    "An immutable object identity may be published once.  Re-publishing byte-identical "
    "canonical content is DUPLICATE_IDENTICAL and succeeds without rewriting; any other "
    "content for the same identity is CONFLICT_DIFFERENT and fails closed."
)


def _fsync_directory(path: Path) -> None:
    handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


@dataclass(frozen=True)
class PublishedObject:
    """A committed object together with its typed publication receipt."""

    receipt: PublicationReceipt
    payload: dict[str, Any]
    raw_bytes: bytes


class DurableObjectStore:
    """A flat, immutable, no-replace object store rooted at one directory."""

    def __init__(self, root: str | os.PathLike[str], *, injector: FaultInjector | None = None) -> None:
        root_path = Path(root)
        if not root_path.is_absolute():
            raise ValueError("the durable store root must be an absolute path")
        if root_path.is_symlink():
            raise ValueError("the durable store root must not be a symlink")
        root_path.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
        resolved = Path(os.path.realpath(root_path))
        if resolved != root_path:
            raise ValueError("the durable store root must equal its canonical resolved path")
        self._root = root_path
        self._injector = injector or NULL_FAULT_INJECTOR
        self._sequence = 0

    @property
    def root(self) -> Path:
        return self._root

    @property
    def injector(self) -> FaultInjector:
        return self._injector

    # -- naming ---------------------------------------------------------------

    @staticmethod
    def object_name(object_kind: str, object_id: str) -> str:
        for token, label in ((object_kind, "object kind"), (object_id, "object id")):
            if not token or "/" in token or "\\" in token or "\x00" in token or token.startswith("."):
                raise ValueError(f"{label} must be a simple, non-hidden name component")
        return f"{object_kind}.{object_id}.json"

    def path_of(self, object_kind: str, object_id: str) -> Path:
        return self._root / self.object_name(object_kind, object_id)

    # -- inspection -----------------------------------------------------------

    def inspect(self, object_kind: str, object_id: str) -> PublicationReceipt:
        """Classify one immutable identity from durable bytes alone."""

        name = self.object_name(object_kind, object_id)
        path = self._root / name
        try:
            raw = self._read_committed(name)
        except FileNotFoundError:
            return PublicationReceipt.create(
                object_kind=object_kind,
                object_id=object_id,
                relative_path=name,
                state="ABSENT",
                byte_count=None,
                content_fingerprint=None,
                verified_bytes=False,
                idempotency_rule=IDEMPOTENCY_RULE,
            )
        try:
            parse_canonical_json(raw, label=str(path))
        except CanonicalizationError:
            return PublicationReceipt.create(
                object_kind=object_kind,
                object_id=object_id,
                relative_path=name,
                state="CORRUPT",
                byte_count=len(raw),
                content_fingerprint=self.content_fingerprint(raw),
                verified_bytes=False,
                idempotency_rule=IDEMPOTENCY_RULE,
            )
        return PublicationReceipt.create(
            object_kind=object_kind,
            object_id=object_id,
            relative_path=name,
            state="PUBLISHED",
            byte_count=len(raw),
            content_fingerprint=self.content_fingerprint(raw),
            verified_bytes=True,
            idempotency_rule=IDEMPOTENCY_RULE,
        )

    def load(self, object_kind: str, object_id: str) -> dict[str, Any]:
        """Reconstruct one committed object, failing closed on corruption."""

        name = self.object_name(object_kind, object_id)
        raw = self._read_committed(name)
        try:
            value = parse_canonical_json(raw, label=name)
        except CanonicalizationError as error:
            raise CorruptDurableObject(f"{name} is not canonical committed content") from error
        if not isinstance(value, dict):
            raise CorruptDurableObject(f"{name} is not a canonical object")
        return value

    def partial_publications(self) -> tuple[str, ...]:
        """Temporary files are detected and never mistaken for committed objects."""

        return tuple(sorted(entry for entry in os.listdir(self._root) if entry.startswith(TEMPORARY_PREFIX)))

    def committed_names(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                entry
                for entry in os.listdir(self._root)
                if entry.endswith(".json") and not entry.startswith(TEMPORARY_PREFIX)
            )
        )

    def _check(self, fault_point: str | None, phase: str) -> None:
        if fault_point is not None:
            self._injector.check(f"{fault_point}:{phase}")

    def _discard_temporary(self, temporary_path: Path) -> None:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            return
        _fsync_directory(self._root)

    @staticmethod
    def content_fingerprint(raw: bytes) -> Fingerprint:
        return fingerprint_bytes(raw, domain=f"{PublicationReceipt.SCHEMA_ID}.content")

    def _read_committed(self, name: str) -> bytes:
        handle = os.open(self._root / name, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            chunks: list[bytes] = []
            while True:
                chunk = os.read(handle, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(handle)

    # -- publication ----------------------------------------------------------

    def publish(
        self,
        *,
        object_kind: str,
        object_id: str,
        payload: dict[str, Any],
        fault_point: str | None = None,
    ) -> PublicationReceipt:
        """Durably publish one immutable object and return its typed receipt.

        The sequence is: serialize canonically, create a temporary file inside
        the target directory with an explicit restrictive mode and no symlink
        following, write, flush, ``fsync`` the file, link the object into place
        with no-replace semantics, ``fsync`` the parent directory, then read the
        committed bytes back and compare them with what was serialized.
        """

        raw = canonical_bytes(payload)
        name = self.object_name(object_kind, object_id)
        content_fp = self.content_fingerprint(raw)

        existing = self.inspect(object_kind, object_id)
        if existing.state == "CORRUPT":
            raise CorruptDurableObject(f"{name} already holds non-canonical bytes")
        if existing.state == "PUBLISHED":
            if existing.content_fingerprint == content_fp:
                return PublicationReceipt.create(
                    object_kind=object_kind,
                    object_id=object_id,
                    relative_path=name,
                    state="DUPLICATE_IDENTICAL",
                    byte_count=len(raw),
                    content_fingerprint=content_fp,
                    verified_bytes=True,
                    idempotency_rule=IDEMPOTENCY_RULE,
                )
            raise PublicationConflict(f"{name} already holds a different immutable object")

        self._sequence += 1
        temporary = f"{TEMPORARY_PREFIX}{os.getpid()}-{self._sequence}-{object_kind}.{object_id}"
        temporary_path = self._root / temporary
        handle = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            FILE_MODE,
        )
        try:
            # A simulated crash must freeze the durable state exactly as a real
            # crash would, so InjectedFault deliberately skips every cleanup
            # step below.  Only the descriptor is released, which no observer of
            # the filesystem can distinguish from process death.
            self._check(fault_point, PUBLICATION_PHASE_TEMP_WRITE)
            written = 0
            while written < len(raw):
                written += os.write(handle, raw[written:])
            os.fsync(handle)
            os.close(handle)
            handle = -1
            self._check(fault_point, PUBLICATION_PHASE_AFTER_FILE_FSYNC)
            try:
                # link() never replaces an existing name, so a concurrent or
                # replayed publication cannot silently overwrite a different
                # object.  This is the atomic commit point.
                os.link(temporary_path, self._root / name)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise
                raise PublicationConflict(f"{name} was published concurrently") from error
            self._check(fault_point, PUBLICATION_PHASE_AFTER_COMMIT_BEFORE_DIR_FSYNC)
            _fsync_directory(self._root)
            self._check(fault_point, PUBLICATION_PHASE_AFTER_COMMIT)
        except InjectedFault:
            if handle >= 0:
                os.close(handle)
            raise
        except BaseException:
            if handle >= 0:
                os.close(handle)
            self._discard_temporary(temporary_path)
            raise
        self._discard_temporary(temporary_path)

        readback = self._read_committed(name)
        if readback != raw:
            raise CorruptDurableObject(f"{name} committed bytes differ from the published object")
        return PublicationReceipt.create(
            object_kind=object_kind,
            object_id=object_id,
            relative_path=name,
            state="PUBLISHED",
            byte_count=len(raw),
            content_fingerprint=content_fp,
            verified_bytes=True,
            idempotency_rule=IDEMPOTENCY_RULE,
        )

    def publish_record(self, *, object_kind: str, object_id: str, record: Any, fault_point: str | None = None) -> PublicationReceipt:
        """Publish any typed record that exposes a canonical ``to_dict``."""

        to_dict: Callable[[], dict[str, Any]] = record.to_dict
        return self.publish(
            object_kind=object_kind,
            object_id=object_id,
            payload=to_dict(),
            fault_point=fault_point,
        )


__all__ = [
    "CorruptDurableObject",
    "DurableObjectStore",
    "FAULT_POINTS",
    "FaultInjector",
    "IDEMPOTENCY_RULE",
    "InjectedFault",
    "NULL_FAULT_INJECTOR",
    "PUBLICATION_PHASES",
    "PublicationConflict",
    "PublishedObject",
    "STAGE_PROPOSAL_PUBLICATION",
    "STAGE_RECONCILIATION_PUBLICATION",
    "STAGE_TERMINAL_RECEIPT_PUBLICATION",
    "FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT",
    "FAULT_AFTER_PROPOSAL_FSYNC_BEFORE_RENAME",
    "FAULT_AFTER_PROPOSAL_PUBLICATION",
    "FAULT_AFTER_PROPOSAL_RENAME_BEFORE_DIR_FSYNC",
    "FAULT_AFTER_RESERVATION_PUBLICATION",
    "FAULT_AFTER_STARTED_BEFORE_EFFECT",
    "FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION",
    "FAULT_BEFORE_PROPOSAL_PUBLICATION",
    "FAULT_BEFORE_RESERVATION_PUBLICATION",
    "FAULT_BEFORE_STARTED_PUBLICATION",
    "FAULT_DURING_PROPOSAL_TEMP_WRITE",
    "FAULT_DURING_RECONCILIATION_PUBLICATION",
    "FAULT_DURING_TERMINAL_RECEIPT_PUBLICATION",
]
