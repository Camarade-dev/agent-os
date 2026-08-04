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
        # A ledger entry is a claim about what happened, never a verdict on
        # whether that claim checks out.  Reconciliation lives in the separate
        # FinalReconciliation record, so the only admissible state here is the
        # pending one.
        _require_member(self.final_reconciliation_state, ("PENDING_VERIFICATION",), "final_reconciliation_state")
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
        #: Proposals the durable index opened but never closed.  A crash between
        #: an effect and the event that closes it produces exactly one of these,
        #: and it is reported rather than hidden.
        self.open_proposal_ids: tuple[str, ...] = ()

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

    def adopt(self, entries: tuple[EffectLedgerEntry, ...]) -> "RunEffectLedger":
        """Take the durable history as this ledger's contents.

        A restarted process legitimately begins with nothing in memory, and the
        durable event index is the authority on what the run actually did, so an
        empty ledger is refilled from bytes.  A ledger that already holds entries
        may only be *extended* by the durable history: whatever it recorded must
        still be there, in the same order, at the same positions.  Anything else
        -- a different proposal, a different order, a shorter history than this
        object already witnessed -- is a contradiction rather than something to
        overwrite, because it would mean this ledger has been recording a run the
        durable evidence does not describe.
        """

        current = tuple(entry.proposal_id for entry in self._entries)
        derived = tuple(entry.proposal_id for entry in entries)
        if current != derived[: len(current)]:
            raise ObservationError(
                "the in-memory effect ledger contradicts the durable run index; it records "
                f"{list(current)} where the durable history records {list(derived)}"
            )
        for existing, replacement in zip(self._entries, entries):
            if existing.record_fingerprint != replacement.record_fingerprint:
                raise ObservationError(
                    f"the durable ledger entry for {existing.proposal_id} differs from the one this ledger holds"
                )
        self._entries = list(entries)
        return self

    def proposal_ledger_fingerprint(self, *, index_head: str | None = None) -> Fingerprint:
        return fingerprint(
            {
                "run_id": self._run_id,
                # The durable index head binds this fingerprint to the *complete*
                # history rather than to whatever subset happens to be in memory.
                "run_index_head_event_fingerprint": index_head,
                "entry_count": len(self._entries),
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

    def effect_receipt_ledger_fingerprint(self, *, index_head: str | None = None) -> Fingerprint:
        return fingerprint(
            {
                "run_id": self._run_id,
                "run_index_head_event_fingerprint": index_head,
                "entry_count": len(self._entries),
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
    def verify(
        cls,
        store: Any,
        run_id: str,
        *,
        specification: Any = None,
        specification_fingerprint: Any = None,
        index: Any = None,
        require_closed: bool = True,
    ) -> "RunEffectLedger":
        """Rebuild the ledger from the durable event index and verify every chain.

        The Milestone 2 signature took the proposal identities to verify *from
        the caller*.  A restarted process could therefore hand in an empty tuple
        -- or any convenient subset -- and receive a ledger that verified
        perfectly while omitting every effect the run had already performed.
        History was a parameter.

        It is now derived.  The ordered set of proposals comes from the durable
        run index, which is itself chain-verified against its committed head, so
        no caller can choose what is checked.  For every indexed proposal the
        whole typed chain is reconciled; an effect-bearing one must have a ledger
        entry whose fingerprint the index already recorded, and a refused one
        must have none.  A ledger entry in the store that the index never
        recorded is a surplus record and fails closed.

        ``require_closed`` is the one dial, and it does *not* select history: it
        decides what happens to a proposal the index opened and never closed.
        A crash between an effect and the event that closes it leaves exactly
        that state, and a restarted controller must still be able to look at the
        run in order to refuse replaying it.  With ``require_closed=False`` such
        a proposal is excluded from the ledger and named in
        :attr:`open_proposal_ids` instead of failing the whole derivation; every
        *closed* proposal is verified exactly as strictly either way.
        """

        from .reconciliation import reconcile_typed_chain  # circular at module scope
        from .run_index import DurableRunIndex

        run_index = index if index is not None else DurableRunIndex(store, run_id)
        # verify() re-derives the chain from bytes and refuses a gap, a surplus
        # position, a reordering, a foreign record, or an uncommitted head.
        events = run_index.verify()

        ledger = cls(run_id)
        indexed: set[str] = set()
        still_open: list[str] = []
        for proposal_id in run_index.indexed_proposal_ids():
            indexed.add(proposal_id)
            terminal = run_index.terminal_event_for(proposal_id)
            if terminal is None:
                if require_closed:
                    raise ObservationError(
                        f"proposal {proposal_id} is indexed but never closed; the run's history is incomplete"
                    )
                still_open.append(proposal_id)
                continue
            final = reconcile_typed_chain(
                store,
                run_id=run_id,
                proposal_id=proposal_id,
                specification=specification,
                specification_fingerprint=specification_fingerprint,
            )
            if not final.verified:
                raise ObservationError(
                    f"the durable chain for {proposal_id} does not reconcile: {final.refusal_code}"
                )
            if not terminal.effect_crossed_boundary:
                # A refusal is represented by the absence of a ledger entry, and
                # that absence is checked rather than assumed.
                if store.inspect(LEDGER_OBJECT_KIND, proposal_id).state != "ABSENT":
                    raise ObservationError(
                        f"proposal {proposal_id} was indexed as refused but carries a ledger entry"
                    )
                continue
            entry = EffectLedgerEntry.from_dict(store.load(LEDGER_OBJECT_KIND, proposal_id))
            if terminal.ledger_entry_fingerprint != entry.record_fingerprint:
                raise ObservationError(
                    f"the run index records a different ledger entry for {proposal_id} than the store holds"
                )
            if terminal.effect_receipt_fingerprint != entry.effect_receipt_fingerprint:
                raise ObservationError(
                    f"the run index records a different effect receipt for {proposal_id} than the ledger entry"
                )
            ledger.append(entry)

        surplus = sorted(
            name[len(f"{LEDGER_OBJECT_KIND}.") : -len(".json")]
            for name in store.committed_names()
            if name.startswith(f"{LEDGER_OBJECT_KIND}.") and name.endswith(".json")
        )
        unindexed = [proposal_id for proposal_id in surplus if proposal_id not in indexed]
        if unindexed:
            raise ObservationError(
                f"the durable store holds ledger entries the run index never recorded: {unindexed}"
            )
        if len(events) and not indexed:  # pragma: no cover - a chain always starts with a proposal
            raise ObservationError("the run index holds events but records no proposal")
        ledger.open_proposal_ids = tuple(still_open)
        return ledger

    @classmethod
    def restore(
        cls,
        store: Any,
        run_id: str,
        *,
        specification: Any = None,
        specification_fingerprint: Any = None,
        index: Any = None,
    ) -> "RunEffectLedger":
        """Reconstruct a run's complete effect ledger from durable bytes alone."""

        return cls.verify(
            store,
            run_id,
            specification=specification,
            specification_fingerprint=specification_fingerprint,
            index=index,
        )


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
