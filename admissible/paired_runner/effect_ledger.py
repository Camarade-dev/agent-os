"""The provider-free run and effect ledger for Milestone 2.

One :class:`EffectLedgerEntry` binds every durable object produced for one
effect: the experiment specification, the run, the proposal, the decision, the
reservation, the ordered lifecycle receipts, the typed request and result, the
publication receipts, the clock observations, and the physical filesystem, Git,
process, stream, and resource observations.

The ledger is provider-free.  It contains no model identity, no token or cost
metric, no policy decision, and no acceptance verdict.  A future terminal
manifest may cite ledger fingerprints only after :meth:`RunEffectLedger.verify`
has revalidated the typed entries from durable bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar

from .canonical import Fingerprint, fingerprint
from .observation import (
    EFFECT_RECEIPT_LEDGER_FINGERPRINT_DOMAIN,
    PROPOSAL_LEDGER_FINGERPRINT_DOMAIN,
    RECONCILIATION_CLASSIFICATIONS,
    SCHEMA_EFFECT_LEDGER_ENTRY,
    M2_SCHEMA_VERSION,
    ObservationError,
    _decode_fp,
    _decode_optional_fp,
    _decode_strings,
    _encode_fp,
    _encode_optional_fp,
    _encode_strings,
    _M2Record,
    _require_bool,
    _require_int,
    _require_member,
    _require_text,
    m2_schema_descriptor,
)
from .schemas import EFFECT_CLASSIFICATIONS


LEDGER_OBJECT_KIND = "effect-ledger-entry"


@dataclass(frozen=True)
class EffectLedgerEntry(_M2Record):
    """The complete durable binding for exactly one effect attempt."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_EFFECT_LEDGER_ENTRY
    LABEL: ClassVar[str] = "effect ledger entry"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "experiment_specification_fingerprint",
        "run_id",
        "condition_id",
        "session_id",
        "proposal_id",
        "proposal_fingerprint",
        "decision_fingerprint",
        "decision_value",
        "reservation_id",
        "reservation_fingerprint",
        "lifecycle_receipt_fingerprints",
        "effect_receipt_fingerprint",
        "tool_name",
        "effect_classification",
        "tool_request_fingerprint",
        "tool_result_fingerprint",
        "publication_receipt_fingerprints",
        "wall_clock_start_unix_ms",
        "wall_clock_end_unix_ms",
        "monotonic_start_ns",
        "monotonic_end_ns",
        "filesystem_observation_before_fingerprint",
        "filesystem_observation_after_fingerprint",
        "git_observation_before_fingerprint",
        "git_observation_after_fingerprint",
        "process_observation_fingerprint",
        "stdout_observation_fingerprint",
        "stderr_observation_fingerprint",
        "resource_observation_fingerprint",
        "effect_crossed_boundary",
        "final_reconciliation_state",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "experiment_specification_fingerprint": _encode_fp,
        "proposal_fingerprint": _encode_fp,
        "decision_fingerprint": _encode_fp,
        "reservation_fingerprint": _encode_optional_fp,
        "lifecycle_receipt_fingerprints": _encode_strings,
        "effect_receipt_fingerprint": _encode_fp,
        "tool_request_fingerprint": _encode_fp,
        "tool_result_fingerprint": _encode_optional_fp,
        "publication_receipt_fingerprints": _encode_strings,
        "filesystem_observation_before_fingerprint": _encode_optional_fp,
        "filesystem_observation_after_fingerprint": _encode_optional_fp,
        "git_observation_before_fingerprint": _encode_optional_fp,
        "git_observation_after_fingerprint": _encode_optional_fp,
        "process_observation_fingerprint": _encode_optional_fp,
        "stdout_observation_fingerprint": _encode_optional_fp,
        "stderr_observation_fingerprint": _encode_optional_fp,
        "resource_observation_fingerprint": _encode_optional_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "experiment_specification_fingerprint": _decode_fp,
        "proposal_fingerprint": _decode_fp,
        "decision_fingerprint": _decode_fp,
        "reservation_fingerprint": _decode_optional_fp,
        "lifecycle_receipt_fingerprints": _decode_strings,
        "effect_receipt_fingerprint": _decode_fp,
        "tool_request_fingerprint": _decode_fp,
        "tool_result_fingerprint": _decode_optional_fp,
        "publication_receipt_fingerprints": _decode_strings,
        "filesystem_observation_before_fingerprint": _decode_optional_fp,
        "filesystem_observation_after_fingerprint": _decode_optional_fp,
        "git_observation_before_fingerprint": _decode_optional_fp,
        "git_observation_after_fingerprint": _decode_optional_fp,
        "process_observation_fingerprint": _decode_optional_fp,
        "stdout_observation_fingerprint": _decode_optional_fp,
        "stderr_observation_fingerprint": _decode_optional_fp,
        "resource_observation_fingerprint": _decode_optional_fp,
    }

    experiment_specification_fingerprint: Fingerprint
    run_id: str
    condition_id: str
    session_id: str
    proposal_id: str
    proposal_fingerprint: Fingerprint
    decision_fingerprint: Fingerprint
    decision_value: str
    reservation_id: str | None
    reservation_fingerprint: Fingerprint | None
    lifecycle_receipt_fingerprints: tuple[str, ...]
    effect_receipt_fingerprint: Fingerprint
    tool_name: str
    effect_classification: str
    tool_request_fingerprint: Fingerprint
    tool_result_fingerprint: Fingerprint | None
    publication_receipt_fingerprints: tuple[str, ...]
    wall_clock_start_unix_ms: int
    wall_clock_end_unix_ms: int
    monotonic_start_ns: int
    monotonic_end_ns: int
    filesystem_observation_before_fingerprint: Fingerprint | None
    filesystem_observation_after_fingerprint: Fingerprint | None
    git_observation_before_fingerprint: Fingerprint | None
    git_observation_after_fingerprint: Fingerprint | None
    process_observation_fingerprint: Fingerprint | None
    stdout_observation_fingerprint: Fingerprint | None
    stderr_observation_fingerprint: Fingerprint | None
    resource_observation_fingerprint: Fingerprint | None
    effect_crossed_boundary: bool
    final_reconciliation_state: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "EffectLedgerEntry":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        for name in ("run_id", "condition_id", "session_id", "proposal_id", "tool_name", "decision_value"):
            _require_text(getattr(self, name), name, max_bytes=256)
        _require_member(self.condition_id, ("DIRECT", "GOVERNED"), "condition_id")
        _require_member(self.effect_classification, EFFECT_CLASSIFICATIONS, "effect_classification")
        _require_member(self.final_reconciliation_state, RECONCILIATION_CLASSIFICATIONS, "final_reconciliation_state")
        _require_bool(self.effect_crossed_boundary, "effect_crossed_boundary")
        for name in (
            "experiment_specification_fingerprint",
            "proposal_fingerprint",
            "decision_fingerprint",
            "effect_receipt_fingerprint",
            "tool_request_fingerprint",
        ):
            getattr(self, name).validated()
        for name in (
            "reservation_fingerprint",
            "tool_result_fingerprint",
            "filesystem_observation_before_fingerprint",
            "filesystem_observation_after_fingerprint",
            "git_observation_before_fingerprint",
            "git_observation_after_fingerprint",
            "process_observation_fingerprint",
            "stdout_observation_fingerprint",
            "stderr_observation_fingerprint",
            "resource_observation_fingerprint",
        ):
            value = getattr(self, name)
            if value is not None:
                value.validated()
        if self.reservation_id is not None:
            _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        if (self.reservation_id is None) != (self.reservation_fingerprint is None):
            raise ObservationError("a reservation identity and its fingerprint travel together")
        _encode_strings(self.lifecycle_receipt_fingerprints)
        _encode_strings(self.publication_receipt_fingerprints)
        for name in ("wall_clock_start_unix_ms", "wall_clock_end_unix_ms", "monotonic_start_ns", "monotonic_end_ns"):
            _require_int(getattr(self, name), name)
        if self.monotonic_end_ns < self.monotonic_start_ns:
            raise ObservationError("ledger monotonic observations must not go backwards")
        if self.effect_crossed_boundary and self.reservation_fingerprint is None:
            raise ObservationError("an effect can only cross the boundary under a durable reservation")
        if not self.effect_crossed_boundary and self.tool_result_fingerprint is not None:
            raise ObservationError("a typed result exists only for an effect that crossed the boundary")
        if self.effect_classification != "PROCESS_EXECUTION":
            for name in ("process_observation_fingerprint", "stdout_observation_fingerprint", "stderr_observation_fingerprint"):
                if getattr(self, name) is not None:
                    raise ObservationError(f"{name} belongs to a process-executing effect only")


class RunEffectLedger:
    """The ordered, durable ledger of every effect attempted in one run."""

    def __init__(self, run_id: str) -> None:
        _require_text(run_id, "run_id", max_bytes=256)
        self._run_id = run_id
        self._entries: list[EffectLedgerEntry] = []

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def entries(self) -> tuple[EffectLedgerEntry, ...]:
        return tuple(self._entries)

    def append(self, entry: EffectLedgerEntry) -> EffectLedgerEntry:
        entry.validated()
        if entry.run_id != self._run_id:
            raise ObservationError("an entry from another run cannot join this ledger")
        if any(existing.proposal_id == entry.proposal_id for existing in self._entries):
            raise ObservationError("one proposal may appear in the ledger exactly once")
        self._entries.append(entry)
        return entry

    def proposal_ledger_fingerprint(self) -> Fingerprint:
        return fingerprint(
            {
                "run_id": self._run_id,
                "proposals": [
                    {
                        "proposal_id": entry.proposal_id,
                        "proposal_fingerprint": entry.proposal_fingerprint.to_dict(),
                    }
                    for entry in self._entries
                ],
            },
            domain=PROPOSAL_LEDGER_FINGERPRINT_DOMAIN,
        )

    def effect_receipt_ledger_fingerprint(self) -> Fingerprint:
        return fingerprint(
            {
                "run_id": self._run_id,
                "receipts": [
                    {
                        "proposal_id": entry.proposal_id,
                        "effect_receipt_fingerprint": entry.effect_receipt_fingerprint.to_dict(),
                        "ledger_entry_fingerprint": entry.record_fingerprint.to_dict(),
                    }
                    for entry in self._entries
                ],
            },
            domain=EFFECT_RECEIPT_LEDGER_FINGERPRINT_DOMAIN,
        )

    @classmethod
    def verify(cls, store: Any, run_id: str, proposal_ids: tuple[str, ...]) -> "RunEffectLedger":
        """Rebuild and revalidate the ledger from durable bytes only.

        Nothing in-memory is trusted: each entry is re-read from the store,
        re-parsed canonically, and re-validated as a typed record before it is
        admitted.  A corrupt or missing entry fails closed.
        """

        ledger = cls(run_id)
        for proposal_id in proposal_ids:
            payload = store.load(LEDGER_OBJECT_KIND, proposal_id)
            ledger.append(EffectLedgerEntry.from_dict(payload))
        return ledger


M2_LEDGER_SCHEMAS = {
    EffectLedgerEntry.SCHEMA_ID: m2_schema_descriptor(
        EffectLedgerEntry.SCHEMA_ID,
        "EffectLedgerEntry",
        ("schema_id", "schema_version") + EffectLedgerEntry.FIELDS + ("record_fingerprint",),
    )
}
for _descriptor in M2_LEDGER_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.effect_ledger")


__all__ = [
    "EffectLedgerEntry",
    "LEDGER_OBJECT_KIND",
    "M2_LEDGER_SCHEMAS",
    "M2_SCHEMA_VERSION",
    "RunEffectLedger",
]
