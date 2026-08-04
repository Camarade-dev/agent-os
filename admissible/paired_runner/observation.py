"""Typed, versioned Milestone 2 observation records.

Every physical fact the shared substrate learns is represented here as an
immutable record with an exact field set, a domain-separated fingerprint, and
an explicit availability status when the platform cannot guarantee a metric.
The records have the same schema for a future DIRECT run and a future GOVERNED
run: nothing in this module is condition-specific, and no record carries a
policy decision, an owner authorization, a provider identity, or a task
acceptance.

A metric that the host or the standard library cannot supply is recorded as an
explicit availability value with a ``None`` measurement.  It is never recorded
as zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar

from .canonical import Fingerprint, fingerprint, require_exact_keys
from .schemas import PACKAGE_PREFIX, SchemaDescriptor


M2_SCHEMA_VERSION = 2
M2_PREFIX = f"{PACKAGE_PREFIX}.m2"

SCHEMA_PUBLICATION_RECEIPT = f"{M2_PREFIX}.publication_receipt"
SCHEMA_FILESYSTEM_OBSERVATION = f"{M2_PREFIX}.filesystem_observation"
SCHEMA_GIT_OBSERVATION = f"{M2_PREFIX}.git_observation"
SCHEMA_PROCESS_OBSERVATION = f"{M2_PREFIX}.process_observation"
SCHEMA_STREAM_OBSERVATION = f"{M2_PREFIX}.stream_observation"
SCHEMA_RESOURCE_OBSERVATION = f"{M2_PREFIX}.resource_observation"
SCHEMA_EFFECT_RECONCILIATION_REPORT = f"{M2_PREFIX}.effect_reconciliation_report"
SCHEMA_LIFECYCLE_RECORD = f"{M2_PREFIX}.lifecycle_record"
SCHEMA_EFFECT_LEDGER_ENTRY = f"{M2_PREFIX}.effect_ledger_entry"

# The four fixed domains a future terminal manifest will name.  Milestone 2
# does not implement evaluator acceptance, but it removes any ambiguity about
# which typed object stands behind each terminal fingerprint field.
PROPOSAL_LEDGER_FINGERPRINT_DOMAIN = f"{M2_PREFIX}.proposal_ledger.fingerprint"
EFFECT_RECEIPT_LEDGER_FINGERPRINT_DOMAIN = f"{M2_PREFIX}.effect_receipt_ledger.fingerprint"
BUDGET_RESOURCE_OBSERVATION_FINGERPRINT_DOMAIN = f"{SCHEMA_RESOURCE_OBSERVATION}.fingerprint"
REPOSITORY_FILESYSTEM_OBSERVATION_FINGERPRINT_DOMAIN = f"{SCHEMA_FILESYSTEM_OBSERVATION}.fingerprint"

TERMINAL_LEDGER_FINGERPRINT_DOMAINS = {
    "proposal_ledger_fingerprint": PROPOSAL_LEDGER_FINGERPRINT_DOMAIN,
    "effect_receipt_ledger_fingerprint": EFFECT_RECEIPT_LEDGER_FINGERPRINT_DOMAIN,
    "budget_resource_observation_fingerprint": BUDGET_RESOURCE_OBSERVATION_FINGERPRINT_DOMAIN,
    "repository_filesystem_observation_fingerprint": REPOSITORY_FILESYSTEM_OBSERVATION_FINGERPRINT_DOMAIN,
}

# Publication lifecycle of one immutable durable object.
PUBLICATION_STATES = (
    "ABSENT",
    "RESERVED",
    "PUBLISHED",
    "DUPLICATE_IDENTICAL",
    "CONFLICT_DIFFERENT",
    "CORRUPT",
    "AMBIGUOUS",
)

# Explicit measurement availability; a missing metric is never zero.
AVAILABILITY_VALUES = (
    "OBSERVED",
    "OBSERVED_BEST_EFFORT",
    "UNAVAILABLE_ON_PLATFORM",
    "NOT_MEASURED",
)

GIT_AVAILABILITY_VALUES = (
    "OBSERVED",
    "REPOSITORY_ABSENT",
    "GIT_EXECUTABLE_UNAVAILABLE",
    "GIT_COMMAND_FAILED",
    # Git is process-capable, so it is never run before the proposal is durable.
    # A pre-proposal binding records this instead of executing anything.
    "NOT_OBSERVED_BEFORE_DURABLE_PROPOSAL",
    # The capsule that would confine the observer is unavailable, so no Git
    # process is started at all.
    "GIT_SANDBOX_UNAVAILABLE",
)

TEXT_DECODE_STATUSES = (
    "UTF8_DECODED",
    "UTF8_DECODED_AFTER_BOUNDARY_TRIM",
    "REFUSED_NON_UTF8",
    "NOT_RETAINED",
)

RECONCILIATION_CLASSIFICATIONS = (
    # The only state an immutable ledger entry may ever be published in.  A
    # ledger entry that predeclared its own successful reconciliation would be
    # both the claim and its own evidence.
    "PENDING_VERIFICATION",
    "NO_DURABLE_STATE",
    "PROPOSAL_ONLY_NO_EFFECT_POSSIBLE",
    "RESERVED_NO_EFFECT_POSSIBLE",
    "STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION",
    "STARTED_AMBIGUOUS_READ_ONLY",
    "TERMINAL_RECEIPT_DURABLE_RECONCILIATION_INCOMPLETE",
    "RECONCILED_COMPLETE",
    "FAILED_CLOSED_CORRUPT_DURABLE_OBJECT",
)

LIFECYCLE_RECORD_KINDS = ("STARTED", "TERMINAL")

#: Whether a filesystem observation covered the whole tree with content bytes.
#: Only ``COMPLETE`` may serve as a final repository fingerprint.
FILESYSTEM_COMPLETENESS_VALUES = (
    "COMPLETE",
    "INCOMPLETE_ENTRY_LIMIT",
    "INCOMPLETE_BYTE_LIMIT",
    "INCOMPLETE_OBSERVATION_ERROR",
    "UNAVAILABLE",
)


class ObservationError(ValueError):
    """A typed observation record is malformed or internally inconsistent."""


def _encode_plain(value: Any, label: str) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise ObservationError(f"{label} has no canonical representation")


def _encode_fp(value: Any) -> dict[str, Any]:
    if not isinstance(value, Fingerprint):
        raise ObservationError("expected a Fingerprint")
    return value.to_dict()


def _encode_optional_fp(value: Any) -> dict[str, Any] | None:
    return None if value is None else _encode_fp(value)


def _encode_strings(value: Any) -> list[str]:
    if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
        raise ObservationError("expected an immutable tuple of strings")
    return list(value)


def _decode_fp(value: Any) -> Fingerprint:
    return Fingerprint.from_dict(value)


def _decode_optional_fp(value: Any) -> Fingerprint | None:
    return None if value is None else Fingerprint.from_dict(value)


def _decode_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ObservationError("expected an array of strings")
    return tuple(value)


def _require_int(value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1, allow_none: bool = False) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ObservationError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _require_bool(value: Any, label: str, *, allow_none: bool = False) -> bool | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, bool):
        raise ObservationError(f"{label} must be a boolean")
    return value


def _require_text(value: Any, label: str, *, max_bytes: int = 4096, allow_none: bool = False, allow_empty: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise ObservationError(f"{label} must be text without NUL")
    if not value and not allow_empty:
        raise ObservationError(f"{label} must not be empty")
    if len(value.encode("utf-8")) > max_bytes:
        raise ObservationError(f"{label} exceeds its byte bound")
    return value


def _require_member(value: Any, allowed: tuple[str, ...], label: str) -> str:
    if value not in allowed:
        raise ObservationError(f"{label} must be one of {allowed}")
    return value


def _require_availability(value: Any, label: str) -> str:
    return _require_member(value, AVAILABILITY_VALUES, label)


def _require_measurement(value: int | None, availability: str, label: str, *, maximum: int = 2**63 - 1) -> int | None:
    """A metric is present exactly when its availability says it was observed."""

    observed = availability in {"OBSERVED", "OBSERVED_BEST_EFFORT"}
    if observed:
        return _require_int(value, label, maximum=maximum)
    if value is not None:
        raise ObservationError(f"{label} must be absent when it was not observed; it is not zero")
    return None


class _M2Record:
    """Shared strict construction, validation, and canonical round-trip."""

    SCHEMA_ID: ClassVar[str]
    FIELDS: ClassVar[tuple[str, ...]]
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {}
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {}
    LABEL: ClassVar[str]

    record_fingerprint: Fingerprint

    @classmethod
    def _fingerprint_domain(cls) -> str:
        return f"{cls.SCHEMA_ID}.fingerprint"

    @classmethod
    def _body_of(cls, values: dict[str, Any]) -> dict[str, Any]:
        body: dict[str, Any] = {"schema_id": cls.SCHEMA_ID, "schema_version": M2_SCHEMA_VERSION}
        for name in cls.FIELDS:
            encoder = cls.ENCODERS.get(name)
            value = values[name]
            body[name] = encoder(value) if encoder is not None else _encode_plain(value, name)
        return body

    @classmethod
    def _new(cls, **values: Any):
        body = cls._body_of(values)
        record = cls(
            **values,
            record_fingerprint=fingerprint(body, domain=cls._fingerprint_domain()),
        )
        return record.validated()

    def _body(self) -> dict[str, Any]:
        return type(self)._body_of({name: getattr(self, name) for name in type(self).FIELDS})

    def _validate_fields(self) -> None:
        raise NotImplementedError

    def validated(self):
        if not isinstance(self.record_fingerprint, Fingerprint):
            raise ObservationError(f"{type(self).LABEL} record fingerprint must be a Fingerprint")
        self.record_fingerprint.validated()
        if self.record_fingerprint.domain != type(self)._fingerprint_domain():
            raise ObservationError(f"{type(self).LABEL} record fingerprint has the wrong domain")
        self._validate_fields()
        if fingerprint(self._body(), domain=type(self)._fingerprint_domain()) != self.record_fingerprint:
            raise ObservationError(f"{type(self).LABEL} record fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "record_fingerprint": self.record_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any):
        keys = {"schema_id", "schema_version", "record_fingerprint"} | set(cls.FIELDS)
        require_exact_keys(data, keys, label=cls.LABEL)
        if data["schema_id"] != cls.SCHEMA_ID or data["schema_version"] != M2_SCHEMA_VERSION:
            raise ObservationError(f"unsupported {cls.LABEL} schema")
        values: dict[str, Any] = {}
        for name in cls.FIELDS:
            decoder = cls.DECODERS.get(name)
            values[name] = decoder(data[name]) if decoder is not None else data[name]
        return cls(
            **values,
            record_fingerprint=Fingerprint.from_dict(data["record_fingerprint"]),
        ).validated()


@dataclass(frozen=True)
class PublicationReceipt(_M2Record):
    """The typed outcome of one durable publication attempt."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_PUBLICATION_RECEIPT
    LABEL: ClassVar[str] = "publication receipt"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "object_kind",
        "object_id",
        "relative_path",
        "state",
        "byte_count",
        "content_fingerprint",
        "verified_bytes",
        "idempotency_rule",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"content_fingerprint": _encode_optional_fp}
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"content_fingerprint": _decode_optional_fp}

    object_kind: str
    object_id: str
    relative_path: str
    state: str
    byte_count: int | None
    content_fingerprint: Fingerprint | None
    verified_bytes: bool
    idempotency_rule: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        object_kind: str,
        object_id: str,
        relative_path: str,
        state: str,
        byte_count: int | None,
        content_fingerprint: Fingerprint | None,
        verified_bytes: bool,
        idempotency_rule: str,
    ) -> "PublicationReceipt":
        return cls._new(
            object_kind=object_kind,
            object_id=object_id,
            relative_path=relative_path,
            state=state,
            byte_count=byte_count,
            content_fingerprint=content_fingerprint,
            verified_bytes=verified_bytes,
            idempotency_rule=idempotency_rule,
        )

    @property
    def durable(self) -> bool:
        """The object's exact bytes are committed and were read back."""

        return self.state in {"PUBLISHED", "DUPLICATE_IDENTICAL"} and self.verified_bytes

    def _validate_fields(self) -> None:
        _require_text(self.object_kind, "object_kind", max_bytes=128)
        _require_text(self.object_id, "object_id", max_bytes=256)
        _require_text(self.relative_path, "relative_path", max_bytes=4096)
        _require_member(self.state, PUBLICATION_STATES, "publication state")
        _require_bool(self.verified_bytes, "verified_bytes")
        _require_text(self.idempotency_rule, "idempotency_rule", max_bytes=512)
        if self.state in {"PUBLISHED", "DUPLICATE_IDENTICAL", "CONFLICT_DIFFERENT"}:
            _require_int(self.byte_count, "byte_count")
            if self.content_fingerprint is None:
                raise ObservationError("a committed or conflicting object must carry its content fingerprint")
            self.content_fingerprint.validated()
        elif self.state in {"ABSENT", "RESERVED"}:
            if self.byte_count is not None or self.content_fingerprint is not None:
                raise ObservationError("an absent or reserved object has no committed bytes")
        else:  # CORRUPT / AMBIGUOUS
            _require_int(self.byte_count, "byte_count", allow_none=True)
            if self.content_fingerprint is not None:
                self.content_fingerprint.validated()
            if self.verified_bytes:
                raise ObservationError("a corrupt or ambiguous publication is never verified")
        if self.state != "PUBLISHED" and self.state != "DUPLICATE_IDENTICAL" and self.verified_bytes:
            raise ObservationError("only a committed object can report verified bytes")


@dataclass(frozen=True)
class FilesystemObservation(_M2Record):
    """A deterministic fingerprint of the workspace tree at one instant."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_FILESYSTEM_OBSERVATION
    LABEL: ClassVar[str] = "filesystem observation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "phase",
        "entry_count",
        "total_regular_file_bytes",
        "truncated",
        "tree_fingerprint",
        "availability",
        "completeness",
        "content_hashed_file_count",
        "error_count",
        "errors",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "tree_fingerprint": _encode_fp,
        "errors": _encode_strings,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "tree_fingerprint": _decode_fp,
        "errors": _decode_strings,
    }

    phase: str
    entry_count: int
    total_regular_file_bytes: int
    truncated: bool
    tree_fingerprint: Fingerprint
    availability: str
    completeness: str
    content_hashed_file_count: int
    error_count: int
    errors: tuple[str, ...]
    record_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        phase: str,
        entry_count: int,
        total_regular_file_bytes: int,
        truncated: bool,
        tree_fingerprint: Fingerprint,
        availability: str = "OBSERVED",
        completeness: str = "COMPLETE",
        content_hashed_file_count: int = 0,
        error_count: int = 0,
        errors: tuple[str, ...] = (),
    ) -> "FilesystemObservation":
        return cls._new(
            phase=phase,
            entry_count=entry_count,
            total_regular_file_bytes=total_regular_file_bytes,
            truncated=truncated,
            tree_fingerprint=tree_fingerprint,
            availability=availability,
            completeness=completeness,
            content_hashed_file_count=content_hashed_file_count,
            error_count=error_count,
            errors=errors,
        )

    @property
    def is_final_repository_fingerprint(self) -> bool:
        """Only a complete observation may stand as a repository fingerprint."""

        return self.availability == "OBSERVED" and self.completeness == "COMPLETE"

    def _validate_fields(self) -> None:
        _require_member(self.phase, ("INITIAL", "BEFORE_EFFECT", "AFTER_EFFECT"), "filesystem observation phase")
        _require_int(self.entry_count, "entry_count")
        _require_int(self.total_regular_file_bytes, "total_regular_file_bytes")
        _require_int(self.content_hashed_file_count, "content_hashed_file_count")
        _require_int(self.error_count, "error_count")
        _require_bool(self.truncated, "truncated")
        self.tree_fingerprint.validated()
        _require_availability(self.availability, "filesystem availability")
        _require_member(self.completeness, FILESYSTEM_COMPLETENESS_VALUES, "filesystem completeness")
        _encode_strings(self.errors)
        for entry in self.errors:
            _require_text(entry, "filesystem observation error", max_bytes=1024)
        if self.error_count != len(self.errors):
            raise ObservationError("every observation error must be recorded, not counted only")
        # An entry that could not be read, or a tree that had to be cut short,
        # is never presented as a complete observation.  Silently skipping an
        # entry and still claiming OBSERVED is exactly the defect this forbids.
        if self.completeness == "COMPLETE" and (self.errors or self.truncated):
            raise ObservationError(
                "a complete filesystem observation has no errors and is not truncated"
            )
        if self.completeness != "COMPLETE" and self.availability == "OBSERVED":
            raise ObservationError(
                "an incomplete filesystem observation must not claim the OBSERVED availability"
            )


@dataclass(frozen=True)
class GitObservation(_M2Record):
    """Git HEAD, index, and worktree status when Git is physically usable."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_GIT_OBSERVATION
    LABEL: ClassVar[str] = "git observation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "phase",
        "availability",
        "repository_present",
        "head_commit",
        "index_dirty",
        "worktree_dirty",
        "untracked_present",
        "status_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"status_fingerprint": _encode_optional_fp}
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"status_fingerprint": _decode_optional_fp}

    phase: str
    availability: str
    repository_present: bool
    head_commit: str | None
    index_dirty: bool | None
    worktree_dirty: bool | None
    untracked_present: bool | None
    status_fingerprint: Fingerprint | None
    record_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        phase: str,
        availability: str,
        repository_present: bool,
        head_commit: str | None = None,
        index_dirty: bool | None = None,
        worktree_dirty: bool | None = None,
        untracked_present: bool | None = None,
        status_fingerprint: Fingerprint | None = None,
    ) -> "GitObservation":
        return cls._new(
            phase=phase,
            availability=availability,
            repository_present=repository_present,
            head_commit=head_commit,
            index_dirty=index_dirty,
            worktree_dirty=worktree_dirty,
            untracked_present=untracked_present,
            status_fingerprint=status_fingerprint,
        )

    def _validate_fields(self) -> None:
        _require_member(self.phase, ("INITIAL", "BEFORE_EFFECT", "AFTER_EFFECT"), "git observation phase")
        _require_member(self.availability, GIT_AVAILABILITY_VALUES, "git availability")
        _require_bool(self.repository_present, "repository_present")
        if self.availability == "OBSERVED":
            if not self.repository_present:
                raise ObservationError("an observed git status requires a present repository")
            _require_text(self.head_commit, "head_commit", max_bytes=128)
            for name in ("index_dirty", "worktree_dirty", "untracked_present"):
                _require_bool(getattr(self, name), name)
            if self.status_fingerprint is None:
                raise ObservationError("an observed git status requires its status fingerprint")
            self.status_fingerprint.validated()
        else:
            if self.repository_present and self.availability == "REPOSITORY_ABSENT":
                raise ObservationError("git availability contradicts repository presence")
            for name in ("head_commit", "index_dirty", "worktree_dirty", "untracked_present", "status_fingerprint"):
                if getattr(self, name) is not None:
                    raise ObservationError(f"{name} must be absent when git was not observed")


@dataclass(frozen=True)
class ProcessObservation(_M2Record):
    """Everything the controller physically knows about one child process."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_PROCESS_OBSERVATION
    LABEL: ClassVar[str] = "process observation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "process_started",
        "child_pid",
        "child_process_group_id",
        "exit_code",
        "terminating_signal",
        "timed_out",
        "cancelled",
        "start_wall_clock_unix_ms",
        "end_wall_clock_unix_ms",
        "start_monotonic_ns",
        "end_monotonic_ns",
        "duration_ns",
        "termination_escalation",
        "descendants_reaped",
        "start_failure_class",
        "capsule_mechanism",
        "launcher_exit_code",
        "status_document_present",
        "namespace_quiescent",
        "descendants_alive_at_direct_exit",
        "extra_descendants_reaped",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"termination_escalation": _encode_strings}
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"termination_escalation": _decode_strings}

    process_started: bool
    child_pid: int | None
    child_process_group_id: int | None
    exit_code: int | None
    terminating_signal: int | None
    timed_out: bool
    cancelled: bool
    start_wall_clock_unix_ms: int
    end_wall_clock_unix_ms: int
    start_monotonic_ns: int
    end_monotonic_ns: int
    duration_ns: int
    termination_escalation: tuple[str, ...]
    descendants_reaped: bool
    start_failure_class: str | None
    capsule_mechanism: str
    launcher_exit_code: int | None
    status_document_present: bool
    namespace_quiescent: bool
    descendants_alive_at_direct_exit: bool
    extra_descendants_reaped: int
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ProcessObservation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_bool(self.process_started, "process_started")
        _require_bool(self.timed_out, "timed_out")
        _require_bool(self.cancelled, "cancelled")
        _require_bool(self.descendants_reaped, "descendants_reaped")
        for name in ("start_wall_clock_unix_ms", "end_wall_clock_unix_ms", "start_monotonic_ns", "end_monotonic_ns", "duration_ns"):
            _require_int(getattr(self, name), name)
        if self.end_monotonic_ns < self.start_monotonic_ns:
            raise ObservationError("monotonic observations must not go backwards")
        if self.duration_ns != self.end_monotonic_ns - self.start_monotonic_ns:
            raise ObservationError("duration must equal the monotonic difference")
        _encode_strings(self.termination_escalation)
        if self.process_started:
            _require_int(self.child_pid, "child_pid", minimum=1)
            _require_int(self.child_process_group_id, "child_process_group_id", minimum=1)
            if self.start_failure_class is not None:
                raise ObservationError("a started process has no start-failure class")
            if (
                self.exit_code is None
                and self.terminating_signal is None
                and self.status_document_present
            ):
                raise ObservationError("a started and reaped process must record an exit code or a signal")
        else:
            for name in ("child_pid", "child_process_group_id", "exit_code", "terminating_signal"):
                if getattr(self, name) is not None:
                    raise ObservationError(f"{name} must be absent when the process never started")
            if self.termination_escalation:
                raise ObservationError("a process that never started was never terminated")
            _require_text(self.start_failure_class, "start_failure_class", max_bytes=128)
        if self.exit_code is not None:
            _require_int(self.exit_code, "exit_code", minimum=-128, maximum=255)
        if self.terminating_signal is not None:
            _require_int(self.terminating_signal, "terminating_signal", minimum=1, maximum=64)
        _require_text(self.capsule_mechanism, "capsule_mechanism", max_bytes=64)
        for name in ("status_document_present", "namespace_quiescent", "descendants_alive_at_direct_exit"):
            _require_bool(getattr(self, name), name)
        _require_int(self.extra_descendants_reaped, "extra_descendants_reaped")
        if self.launcher_exit_code is not None:
            _require_int(self.launcher_exit_code, "launcher_exit_code", minimum=-128, maximum=255)
        # ``descendants_reaped`` is the physically verified quiescence of the
        # private PID namespace.  It may never be claimed independently of the
        # in-capsule observation that established it.
        if self.descendants_reaped != self.namespace_quiescent and self.process_started:
            raise ObservationError(
                "descendants_reaped must equal the physically observed namespace quiescence"
            )
        if not self.status_document_present and self.process_started:
            if self.namespace_quiescent or self.extra_descendants_reaped:
                raise ObservationError(
                    "no process-domain observation exists, so quiescence must not be claimed"
                )


@dataclass(frozen=True)
class StreamObservation(_M2Record):
    """Full-volume accounting for one output stream with bounded retention."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_STREAM_OBSERVATION
    LABEL: ClassVar[str] = "stream observation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "stream_name",
        "total_bytes",
        "retained_bytes",
        "retained_truncated",
        "stream_fingerprint",
        "text_decode_status",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"stream_fingerprint": _encode_fp}
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"stream_fingerprint": _decode_fp}

    stream_name: str
    total_bytes: int
    retained_bytes: int
    retained_truncated: bool
    stream_fingerprint: Fingerprint
    text_decode_status: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "StreamObservation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_member(self.stream_name, ("stdout", "stderr"), "stream_name")
        _require_int(self.total_bytes, "total_bytes")
        _require_int(self.retained_bytes, "retained_bytes")
        _require_bool(self.retained_truncated, "retained_truncated")
        self.stream_fingerprint.validated()
        _require_member(self.text_decode_status, TEXT_DECODE_STATUSES, "text_decode_status")
        if self.retained_bytes > self.total_bytes:
            raise ObservationError("retained bytes cannot exceed the total stream volume")
        if self.retained_truncated and self.retained_bytes >= self.total_bytes:
            raise ObservationError("a stream can only claim truncation when bytes were dropped")
        if not self.retained_truncated and self.retained_bytes != self.total_bytes and self.text_decode_status != "REFUSED_NON_UTF8":
            raise ObservationError("an untruncated stream must retain every byte it observed")


@dataclass(frozen=True)
class ResourceObservation(_M2Record):
    """Best-effort child resource accounting with explicit availability."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_RESOURCE_OBSERVATION
    LABEL: ClassVar[str] = "resource observation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "child_cpu_user_ms",
        "child_cpu_user_availability",
        "child_cpu_system_ms",
        "child_cpu_system_availability",
        "child_max_rss_kib",
        "child_max_rss_availability",
        "controller_peak_retained_output_bytes",
        "controller_peak_retained_availability",
        "measurement_semantics",
    )

    child_cpu_user_ms: int | None
    child_cpu_user_availability: str
    child_cpu_system_ms: int | None
    child_cpu_system_availability: str
    child_max_rss_kib: int | None
    child_max_rss_availability: str
    controller_peak_retained_output_bytes: int | None
    controller_peak_retained_availability: str
    measurement_semantics: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ResourceObservation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        for value_name, availability_name in (
            ("child_cpu_user_ms", "child_cpu_user_availability"),
            ("child_cpu_system_ms", "child_cpu_system_availability"),
            ("child_max_rss_kib", "child_max_rss_availability"),
            ("controller_peak_retained_output_bytes", "controller_peak_retained_availability"),
        ):
            availability = _require_availability(getattr(self, availability_name), availability_name)
            _require_measurement(getattr(self, value_name), availability, value_name)
        _require_text(self.measurement_semantics, "measurement_semantics", max_bytes=2048)


@dataclass(frozen=True)
class LifecycleRecord(_M2Record):
    """A durable pre-effect or terminal lifecycle marker for one effect."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_LIFECYCLE_RECORD
    LABEL: ClassVar[str] = "lifecycle record"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "kind",
        "run_id",
        "proposal_id",
        "reservation_id",
        "receipt_status",
        "proposal_fingerprint",
        "reservation_fingerprint",
        "effect_classification",
        "wall_clock_unix_ms",
        "monotonic_ns",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "proposal_fingerprint": _encode_fp,
        "reservation_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "proposal_fingerprint": _decode_fp,
        "reservation_fingerprint": _decode_fp,
    }

    kind: str
    run_id: str
    proposal_id: str
    reservation_id: str
    receipt_status: str | None
    proposal_fingerprint: Fingerprint
    reservation_fingerprint: Fingerprint
    effect_classification: str
    wall_clock_unix_ms: int
    monotonic_ns: int
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "LifecycleRecord":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_member(self.kind, LIFECYCLE_RECORD_KINDS, "lifecycle record kind")
        for name in ("run_id", "proposal_id", "reservation_id"):
            _require_text(getattr(self, name), name, max_bytes=256)
        self.proposal_fingerprint.validated()
        self.reservation_fingerprint.validated()
        _require_text(self.effect_classification, "effect_classification", max_bytes=64)
        _require_int(self.wall_clock_unix_ms, "wall_clock_unix_ms")
        _require_int(self.monotonic_ns, "monotonic_ns")
        if self.kind == "STARTED":
            if self.receipt_status is not None:
                raise ObservationError("a STARTED lifecycle record precedes any terminal status")
        else:
            _require_text(self.receipt_status, "receipt_status", max_bytes=64)


@dataclass(frozen=True)
class EffectReconciliationReport(_M2Record):
    """The classification of one effect reconstructed from durable bytes."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_EFFECT_RECONCILIATION_REPORT
    LABEL: ClassVar[str] = "effect reconciliation report"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "run_id",
        "proposal_id",
        "classification",
        "effect_may_have_occurred",
        "replay_permitted",
        "durable_objects_present",
        "durable_objects_absent",
        "partial_publications",
        "corrupt_objects",
        "reconciliation_note",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "durable_objects_present": _encode_strings,
        "durable_objects_absent": _encode_strings,
        "partial_publications": _encode_strings,
        "corrupt_objects": _encode_strings,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "durable_objects_present": _decode_strings,
        "durable_objects_absent": _decode_strings,
        "partial_publications": _decode_strings,
        "corrupt_objects": _decode_strings,
    }

    run_id: str
    proposal_id: str
    classification: str
    effect_may_have_occurred: bool
    replay_permitted: bool
    durable_objects_present: tuple[str, ...]
    durable_objects_absent: tuple[str, ...]
    partial_publications: tuple[str, ...]
    corrupt_objects: tuple[str, ...]
    reconciliation_note: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "EffectReconciliationReport":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.run_id, "run_id", max_bytes=256)
        _require_text(self.proposal_id, "proposal_id", max_bytes=256)
        _require_member(self.classification, RECONCILIATION_CLASSIFICATIONS, "reconciliation classification")
        _require_bool(self.effect_may_have_occurred, "effect_may_have_occurred")
        _require_bool(self.replay_permitted, "replay_permitted")
        for name in ("durable_objects_present", "durable_objects_absent", "partial_publications", "corrupt_objects"):
            values = getattr(self, name)
            _encode_strings(values)
            if tuple(sorted(values)) != values or len(set(values)) != len(values):
                raise ObservationError(f"{name} must be sorted and unique")
        _require_text(self.reconciliation_note, "reconciliation_note", max_bytes=2048)
        if self.effect_may_have_occurred and self.replay_permitted:
            raise ObservationError("an effect that may have occurred can never be automatically replayed")
        if self.corrupt_objects and self.classification != "FAILED_CLOSED_CORRUPT_DURABLE_OBJECT":
            raise ObservationError("a corrupt durable object must fail closed")


def m2_schema_descriptor(schema_id: str, implementation_type: str, required_fields: tuple[str, ...]) -> SchemaDescriptor:
    return SchemaDescriptor(
        schema_id=schema_id,
        version=M2_SCHEMA_VERSION,
        implementation_type=implementation_type,
        canonical_domain=f"{PACKAGE_PREFIX}.canonical",
        fingerprint_domain=f"{schema_id}.fingerprint",
        required_fields=required_fields,
        owning_module="admissible.paired_runner.observation",
    )


def _record_fields(record_type: type[_M2Record]) -> tuple[str, ...]:
    return ("schema_id", "schema_version") + record_type.FIELDS + ("record_fingerprint",)


M2_OBSERVATION_RECORD_TYPES: tuple[type[_M2Record], ...] = (
    PublicationReceipt,
    FilesystemObservation,
    GitObservation,
    ProcessObservation,
    StreamObservation,
    ResourceObservation,
    LifecycleRecord,
    EffectReconciliationReport,
)

M2_OBSERVATION_SCHEMAS = {
    record_type.SCHEMA_ID: m2_schema_descriptor(
        record_type.SCHEMA_ID, record_type.__name__, _record_fields(record_type)
    )
    for record_type in M2_OBSERVATION_RECORD_TYPES
}

_RECORD_TYPES_BY_SCHEMA = {record_type.SCHEMA_ID: record_type for record_type in M2_OBSERVATION_RECORD_TYPES}


def observation_from_dict(data: Any) -> _M2Record:
    """Typed dispatch for any persisted M2 observation record."""

    if not isinstance(data, dict):
        raise ObservationError("an observation record must be an object")
    try:
        record_type = _RECORD_TYPES_BY_SCHEMA[data.get("schema_id")]
    except KeyError as error:
        raise ObservationError("unknown or missing observation schema") from error
    return record_type.from_dict(data)


__all__ = [
    "AVAILABILITY_VALUES",
    "BUDGET_RESOURCE_OBSERVATION_FINGERPRINT_DOMAIN",
    "EFFECT_RECEIPT_LEDGER_FINGERPRINT_DOMAIN",
    "EffectReconciliationReport",
    "FilesystemObservation",
    "GIT_AVAILABILITY_VALUES",
    "GitObservation",
    "LIFECYCLE_RECORD_KINDS",
    "LifecycleRecord",
    "M2_OBSERVATION_SCHEMAS",
    "M2_SCHEMA_VERSION",
    "ObservationError",
    "PROPOSAL_LEDGER_FINGERPRINT_DOMAIN",
    "PUBLICATION_STATES",
    "ProcessObservation",
    "PublicationReceipt",
    "RECONCILIATION_CLASSIFICATIONS",
    "REPOSITORY_FILESYSTEM_OBSERVATION_FINGERPRINT_DOMAIN",
    "ResourceObservation",
    "SCHEMA_EFFECT_LEDGER_ENTRY",
    "StreamObservation",
    "TERMINAL_LEDGER_FINGERPRINT_DOMAINS",
    "TEXT_DECODE_STATUSES",
    "observation_from_dict",
]
