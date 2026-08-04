"""The authoritative, durable, append-only index of one run.

Milestone 2 stored one flat object per proposal and kept the *order* of those
proposals only in a caller-supplied in-memory list.  Three things followed:
a refused proposal left no index entry at all, so the durable record silently
under-reported what the run had attempted; the causal order could be replayed in
any sequence a caller chose; and a restart with an empty in-memory ledger looked
exactly like a run that had never done anything.

This module makes the index itself durable and self-ordering.  Each entry is an
immutable link in a hash chain: it carries its own sequence number and the
fingerprint of the entry before it, so the chain reconstructs from bytes alone
and cannot be reordered, thinned, or extended in the middle without breaking.

The index is provider-free and single-session at Milestone 2.  It records no
model, no transport, no continuation, and no session resumption: it closes only
the durable evidence substrate a later milestone would need.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar

from .canonical import Fingerprint, fingerprint
from .durable_store import CorruptDurableObject, DurableObjectStore
from .observation import (
    M2_PREFIX,
    M2_SCHEMA_VERSION,
    ObservationError,
    _decode_fp,
    _decode_optional_fp,
    _encode_fp,
    _encode_optional_fp,
    _M2Record,
    _require_bool,
    _require_int,
    _require_member,
    _require_text,
    m2_schema_descriptor,
)


SCHEMA_RUN_INDEX_ENTRY = f"{M2_PREFIX}.run_index_entry"
RUN_INDEX_OBJECT_KIND = "run-index-entry"
RUN_INDEX_HEAD_KIND = "run-index-head"
GENESIS_DOMAIN = f"{SCHEMA_RUN_INDEX_ENTRY}.genesis"

#: What the index records happened to a proposal.  Refusals are first-class: a
#: run that refused a proposal attempted that proposal, and the durable record
#: must say so.
INDEX_OUTCOMES = (
    "PROPOSED",
    "DECISION_REFUSED",
    "EFFECT_COMPLETED",
    "EFFECT_FAILED",
    "EFFECT_REFUSED",
    "EFFECT_TIMED_OUT",
    "EFFECT_CANCELLED",
    "AMBIGUOUS_REQUIRES_RECONCILIATION",
)


def genesis_fingerprint(run_id: str) -> Fingerprint:
    """The fixed chain anchor for one run, so entry 0 has a real predecessor."""

    return fingerprint({"run_id": run_id, "genesis": True}, domain=GENESIS_DOMAIN)


@dataclass(frozen=True)
class RunIndexEntry(_M2Record):
    """One immutable link binding a proposal into the run's causal order."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_RUN_INDEX_ENTRY
    LABEL: ClassVar[str] = "run index entry"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "run_id",
        "condition_id",
        "session_id",
        "turn_id",
        "sequence",
        "previous_entry_fingerprint",
        "proposal_id",
        "proposal_fingerprint",
        "decision_value",
        "decision_permits_effect",
        "outcome",
        "effect_crossed_boundary",
        "effect_receipt_fingerprint",
        "ledger_entry_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "previous_entry_fingerprint": _encode_fp,
        "proposal_fingerprint": _encode_fp,
        "effect_receipt_fingerprint": _encode_optional_fp,
        "ledger_entry_fingerprint": _encode_optional_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "previous_entry_fingerprint": _decode_fp,
        "proposal_fingerprint": _decode_fp,
        "effect_receipt_fingerprint": _decode_optional_fp,
        "ledger_entry_fingerprint": _decode_optional_fp,
    }

    run_id: str
    condition_id: str
    session_id: str
    turn_id: str
    sequence: int
    previous_entry_fingerprint: Fingerprint
    proposal_id: str
    proposal_fingerprint: Fingerprint
    decision_value: str
    decision_permits_effect: bool
    outcome: str
    effect_crossed_boundary: bool
    effect_receipt_fingerprint: Fingerprint | None
    ledger_entry_fingerprint: Fingerprint | None
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "RunIndexEntry":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        for name in ("run_id", "condition_id", "session_id", "turn_id", "proposal_id", "decision_value"):
            _require_text(getattr(self, name), name, max_bytes=256)
        _require_member(self.condition_id, ("DIRECT", "GOVERNED"), "condition_id")
        _require_member(self.outcome, INDEX_OUTCOMES, "outcome")
        _require_int(self.sequence, "sequence")
        _require_bool(self.decision_permits_effect, "decision_permits_effect")
        _require_bool(self.effect_crossed_boundary, "effect_crossed_boundary")
        self.previous_entry_fingerprint.validated()
        self.proposal_fingerprint.validated()
        for name in ("effect_receipt_fingerprint", "ledger_entry_fingerprint"):
            value = getattr(self, name)
            if value is not None:
                value.validated()
        if self.effect_crossed_boundary and not self.decision_permits_effect:
            raise ObservationError("an effect cannot cross the boundary under a refusing decision")
        if not self.decision_permits_effect and self.outcome != "DECISION_REFUSED":
            raise ObservationError("a refusing decision indexes exactly one outcome")
        if self.ledger_entry_fingerprint is not None and not self.effect_crossed_boundary:
            raise ObservationError("a ledger entry exists only for an effect that crossed the boundary")


class RunIndexBroken(RuntimeError):
    """The durable run index is missing, reordered, duplicated, or foreign."""


class DurableRunIndex:
    """An append-only hash chain over every proposal a run attempted."""

    def __init__(self, store: DurableObjectStore, run_id: str) -> None:
        _require_text(run_id, "run_id", max_bytes=256)
        self._store = store
        self._run_id = run_id

    @property
    def run_id(self) -> str:
        return self._run_id

    @staticmethod
    def _object_id(run_id: str, sequence: int) -> str:
        # The sequence is part of the immutable identity, so two different
        # entries can never occupy one position and a gap is directly visible.
        return f"{run_id}-{sequence:08d}"

    def head_sequence(self) -> int:
        """The number of durable entries, read from bytes, never from memory.

        A restart calls this instead of trusting an empty in-memory history, so
        a resumed process cannot silently begin as though the run were new.
        """

        sequence = 0
        while self._store.inspect(RUN_INDEX_OBJECT_KIND, self._object_id(self._run_id, sequence)).state != "ABSENT":
            sequence += 1
        return sequence

    def head_fingerprint(self) -> Fingerprint:
        entries = self.load_all()
        return entries[-1].record_fingerprint if entries else genesis_fingerprint(self._run_id)

    def append(
        self,
        *,
        condition_id: str,
        session_id: str,
        turn_id: str,
        proposal_id: str,
        proposal_fingerprint: Fingerprint,
        decision_value: str,
        decision_permits_effect: bool,
        outcome: str,
        effect_crossed_boundary: bool,
        effect_receipt_fingerprint: Fingerprint | None = None,
        ledger_entry_fingerprint: Fingerprint | None = None,
    ) -> RunIndexEntry:
        """Append one link, binding it to the exact current head."""

        entries = self.load_all()
        if any(entry.proposal_id == proposal_id for entry in entries):
            raise RunIndexBroken(f"proposal {proposal_id} is already indexed in this run")
        sequence = len(entries)
        previous = entries[-1].record_fingerprint if entries else genesis_fingerprint(self._run_id)
        entry = RunIndexEntry.create(
            run_id=self._run_id,
            condition_id=condition_id,
            session_id=session_id,
            turn_id=turn_id,
            sequence=sequence,
            previous_entry_fingerprint=previous,
            proposal_id=proposal_id,
            proposal_fingerprint=proposal_fingerprint,
            decision_value=decision_value,
            decision_permits_effect=decision_permits_effect,
            outcome=outcome,
            effect_crossed_boundary=effect_crossed_boundary,
            effect_receipt_fingerprint=effect_receipt_fingerprint,
            ledger_entry_fingerprint=ledger_entry_fingerprint,
        )
        self._store.publish_record(
            object_kind=RUN_INDEX_OBJECT_KIND,
            object_id=self._object_id(self._run_id, sequence),
            record=entry,
        )
        return entry

    def load_all(self) -> tuple[RunIndexEntry, ...]:
        """Reconstruct the chain from durable bytes, failing closed on any break."""

        entries: list[RunIndexEntry] = []
        sequence = 0
        while True:
            object_id = self._object_id(self._run_id, sequence)
            receipt = self._store.inspect(RUN_INDEX_OBJECT_KIND, object_id)
            if receipt.state == "ABSENT":
                break
            if receipt.state == "CORRUPT":
                raise RunIndexBroken(f"run index entry {sequence} is not canonical")
            try:
                entry = RunIndexEntry.from_dict(self._store.load(RUN_INDEX_OBJECT_KIND, object_id))
            except (CorruptDurableObject, ObservationError, ValueError) as error:
                raise RunIndexBroken(f"run index entry {sequence} did not reconstruct: {error}") from error
            entries.append(entry)
            sequence += 1
        self._verify_chain(entries)
        return tuple(entries)

    def _verify_chain(self, entries: list[RunIndexEntry]) -> None:
        seen_proposals: set[str] = set()
        expected_previous = genesis_fingerprint(self._run_id)
        for position, entry in enumerate(entries):
            if entry.run_id != self._run_id:
                # A record from another run cannot be substituted into this one.
                raise RunIndexBroken(f"run index entry {position} belongs to run {entry.run_id}")
            if entry.sequence != position:
                raise RunIndexBroken(
                    f"run index entry at position {position} declares sequence {entry.sequence}"
                )
            if entry.previous_entry_fingerprint != expected_previous:
                # Any omission, reordering, or mid-chain substitution breaks the
                # link here rather than being silently absorbed.
                raise RunIndexBroken(f"run index entry {position} does not follow its predecessor")
            if entry.proposal_id in seen_proposals:
                raise RunIndexBroken(f"proposal {entry.proposal_id} is duplicated in the run index")
            seen_proposals.add(entry.proposal_id)
            expected_previous = entry.record_fingerprint

    def verify(self) -> tuple[RunIndexEntry, ...]:
        """Public, explicit re-verification of the durable chain."""

        return self.load_all()


M2_RUN_INDEX_SCHEMAS = {
    RunIndexEntry.SCHEMA_ID: m2_schema_descriptor(
        RunIndexEntry.SCHEMA_ID,
        "RunIndexEntry",
        ("schema_id", "schema_version") + RunIndexEntry.FIELDS + ("record_fingerprint",),
    )
}
for _descriptor in M2_RUN_INDEX_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.run_index")


__all__ = [
    "DurableRunIndex",
    "INDEX_OUTCOMES",
    "M2_RUN_INDEX_SCHEMAS",
    "M2_SCHEMA_VERSION",
    "RUN_INDEX_OBJECT_KIND",
    "RunIndexBroken",
    "RunIndexEntry",
    "SCHEMA_RUN_INDEX_ENTRY",
    "genesis_fingerprint",
]
