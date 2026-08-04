"""The authoritative, durable, crash-classifiable event chain of one run.

The previous index stored one *final summary* per proposal and discovered its
extent by counting upward from sequence zero until a name was absent.  Three
consequences followed, and the independent audit demonstrated all three:

* deleting an interior entry produced a shorter chain that verified perfectly,
  because the scan stopped at the gap and never looked past it -- the run's
  causal order silently under-reported itself, and the shipped test asserted
  that truncated length as the expected result;
* deleting the newest entry was indistinguishable from a run that had always
  been that short, because nothing durable stated how far the run had got;
* a one-entry-per-proposal summary cannot represent a crash *between* the
  proposal and its outcome at all, so a completed effect whose process died
  before the summary was written left a real effect with no index entry.

This module replaces that with an ordered event chain plus an explicit committed
head:

``run-index-event`` objects
    Immutable, hash-chained links.  Each carries its own sequence, the
    fingerprint of the event before it, and the exact transition it records --
    proposal published, decision published, reservation published, effect
    started, terminal receipt published, typed reconciliation published, or a
    refusal, failure, or ambiguity.  A proposal is indexed *before* any effect
    is possible, so no effect can exist outside the run's causal order.

``run-index-anchor``
    The committed head: run id, head sequence, and the head event's fingerprint.
    It is the one replaceable object in the durable store and it advances only
    after the event it commits is durable.

Reconstruction scans *every* durable name belonging to the run rather than
counting until absence, so a gap, a surplus position, a duplicate, a reordering,
a foreign record, a missing tail relative to the committed head, and an anchor
that outruns its events are each a refusal.

The one residual weakness is stated rather than hidden: deleting the newest
event *and* rewinding the anchor to a still-valid earlier head is a rollback
that no purely local record can detect.  Detecting it requires an anti-rollback
anchor held outside this store -- a witness, a monotonic counter, or an external
attestation -- which Milestone 2 deliberately does not implement.
:meth:`DurableRunIndex.head_anchor` is the exact value such an external anchor
would pin.

The index is provider-free and single-session at Milestone 2.  It records no
model, no transport, no continuation, and no session resumption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar

from .canonical import Fingerprint, fingerprint
from .durable_store import (
    FAULT_AFTER_INDEX_EVENT_BEFORE_ANCHOR,
    FAULT_BEFORE_INDEX_EVENT_PUBLICATION,
    STAGE_INDEX_ANCHOR_UPDATE,
    STAGE_INDEX_EVENT_PUBLICATION,
    CorruptDurableObject,
    DurableObjectStore,
    NULL_FAULT_INJECTOR,
)
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


SCHEMA_RUN_INDEX_EVENT = f"{M2_PREFIX}.run_index_event"
SCHEMA_RUN_INDEX_ANCHOR = f"{M2_PREFIX}.run_index_anchor"
RUN_INDEX_OBJECT_KIND = "run-index-event"
RUN_INDEX_ANCHOR_KIND = "run-index-anchor"
GENESIS_DOMAIN = f"{SCHEMA_RUN_INDEX_EVENT}.genesis"

#: How wide a sequence number is in an object identity.  It is fixed so a gap is
#: a missing *name* rather than an ambiguous numbering.
SEQUENCE_WIDTH = 8

#: The transitions the chain records.  Every one of them is durable before the
#: next step of the substrate proceeds.
EVENT_KINDS = (
    "PROPOSAL_PUBLISHED",
    "DECISION_PUBLISHED",
    "RESERVATION_PUBLISHED",
    "EFFECT_STARTED",
    "TERMINAL_RECEIPT_PUBLISHED",
    "RECONCILIATION_PUBLISHED",
    "DECISION_REFUSED",
    "EFFECT_REFUSED_BEFORE_START",
    "EFFECT_AMBIGUOUS",
)

#: Events that close a proposal.  Exactly one of these exists per proposal in a
#: complete run, and each carries the outcome.
TERMINAL_EVENT_KINDS = (
    "RECONCILIATION_PUBLISHED",
    "DECISION_REFUSED",
    "EFFECT_REFUSED_BEFORE_START",
    "EFFECT_AMBIGUOUS",
)

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

#: The classification of the durable index as a whole, read from bytes.
INDEX_STATES = ("EMPTY", "COMMITTED", "HEAD_UPDATE_PENDING")


def genesis_fingerprint(run_id: str) -> Fingerprint:
    """The fixed chain anchor for one run, so event 0 has a real predecessor."""

    return fingerprint({"run_id": run_id, "genesis": True}, domain=GENESIS_DOMAIN)


@dataclass(frozen=True)
class RunIndexEvent(_M2Record):
    """One immutable link recording one transition of one proposal."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_RUN_INDEX_EVENT
    LABEL: ClassVar[str] = "run index event"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "run_id",
        "condition_id",
        "session_id",
        "turn_id",
        "sequence",
        "previous_event_fingerprint",
        "event_kind",
        "proposal_id",
        "proposal_fingerprint",
        "decision_value",
        "decision_permits_effect",
        "outcome",
        "effect_crossed_boundary",
        "effect_receipt_fingerprint",
        "ledger_entry_fingerprint",
        "final_reconciliation_fingerprint",
        "capsule_runtime_manifest_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "previous_event_fingerprint": _encode_fp,
        "proposal_fingerprint": _encode_fp,
        "effect_receipt_fingerprint": _encode_optional_fp,
        "ledger_entry_fingerprint": _encode_optional_fp,
        "final_reconciliation_fingerprint": _encode_optional_fp,
        "capsule_runtime_manifest_fingerprint": _encode_optional_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "previous_event_fingerprint": _decode_fp,
        "proposal_fingerprint": _decode_fp,
        "effect_receipt_fingerprint": _decode_optional_fp,
        "ledger_entry_fingerprint": _decode_optional_fp,
        "final_reconciliation_fingerprint": _decode_optional_fp,
        "capsule_runtime_manifest_fingerprint": _decode_optional_fp,
    }

    run_id: str
    condition_id: str
    session_id: str
    turn_id: str
    sequence: int
    previous_event_fingerprint: Fingerprint
    event_kind: str
    proposal_id: str
    proposal_fingerprint: Fingerprint
    decision_value: str | None
    decision_permits_effect: bool | None
    outcome: str | None
    effect_crossed_boundary: bool
    effect_receipt_fingerprint: Fingerprint | None
    ledger_entry_fingerprint: Fingerprint | None
    final_reconciliation_fingerprint: Fingerprint | None
    capsule_runtime_manifest_fingerprint: Fingerprint | None
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "RunIndexEvent":
        for name in (
            "decision_value",
            "decision_permits_effect",
            "outcome",
            "effect_receipt_fingerprint",
            "ledger_entry_fingerprint",
            "final_reconciliation_fingerprint",
            "capsule_runtime_manifest_fingerprint",
        ):
            values.setdefault(name, None)
        values.setdefault("effect_crossed_boundary", False)
        return cls._new(**values)

    @property
    def is_terminal(self) -> bool:
        return self.event_kind in TERMINAL_EVENT_KINDS

    def _validate_fields(self) -> None:
        for name in ("run_id", "condition_id", "session_id", "turn_id", "proposal_id"):
            _require_text(getattr(self, name), name, max_bytes=256)
        _require_member(self.condition_id, ("DIRECT", "GOVERNED"), "condition_id")
        _require_member(self.event_kind, EVENT_KINDS, "event_kind")
        _require_int(self.sequence, "sequence")
        _require_bool(self.effect_crossed_boundary, "effect_crossed_boundary")
        self.previous_event_fingerprint.validated()
        self.proposal_fingerprint.validated()
        for name in (
            "effect_receipt_fingerprint",
            "ledger_entry_fingerprint",
            "final_reconciliation_fingerprint",
            "capsule_runtime_manifest_fingerprint",
        ):
            value = getattr(self, name)
            if value is not None:
                value.validated()
        if self.decision_value is not None:
            _require_text(self.decision_value, "decision_value", max_bytes=256)
        if self.decision_permits_effect is not None:
            _require_bool(self.decision_permits_effect, "decision_permits_effect")

        # A terminal event closes a proposal and must say how; a non-terminal
        # event records a transition and must not pre-announce an outcome.
        if self.is_terminal:
            _require_member(self.outcome, INDEX_OUTCOMES, "outcome")
        elif self.outcome is not None:
            raise ObservationError("only a terminal event carries an outcome")

        if self.event_kind == "PROPOSAL_PUBLISHED":
            if self.decision_value is not None or self.decision_permits_effect is not None:
                raise ObservationError("a proposal event precedes any decision")
        elif self.decision_value is None or self.decision_permits_effect is None:
            raise ObservationError(f"a {self.event_kind} event follows a decision and must name it")

        if self.effect_crossed_boundary:
            if self.event_kind not in {"TERMINAL_RECEIPT_PUBLISHED", "RECONCILIATION_PUBLISHED", "EFFECT_AMBIGUOUS"}:
                raise ObservationError("only a post-effect event may report crossing the boundary")
            if not self.decision_permits_effect:
                raise ObservationError("an effect cannot cross the boundary under a refusing decision")
        if self.event_kind in {"RESERVATION_PUBLISHED", "EFFECT_STARTED"} and not self.decision_permits_effect:
            raise ObservationError("a refusing decision produces no reservation and no started effect")
        if self.event_kind == "DECISION_REFUSED" and self.decision_permits_effect:
            raise ObservationError("a refusal event contradicts a permitting decision")
        if self.ledger_entry_fingerprint is not None and not self.effect_crossed_boundary:
            raise ObservationError("a ledger entry exists only for an effect that crossed the boundary")
        if self.final_reconciliation_fingerprint is not None and self.event_kind != "RECONCILIATION_PUBLISHED":
            raise ObservationError("only the reconciliation event binds the final reconciliation record")


@dataclass(frozen=True)
class RunIndexAnchor(_M2Record):
    """The durable committed head: how far this run's chain actually got."""

    SCHEMA_ID: ClassVar[str] = SCHEMA_RUN_INDEX_ANCHOR
    LABEL: ClassVar[str] = "run index anchor"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "run_id",
        "head_sequence",
        "event_count",
        "head_event_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"head_event_fingerprint": _encode_fp}
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {"head_event_fingerprint": _decode_fp}

    run_id: str
    head_sequence: int
    event_count: int
    head_event_fingerprint: Fingerprint
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "RunIndexAnchor":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.run_id, "run_id", max_bytes=256)
        _require_int(self.head_sequence, "head_sequence")
        _require_int(self.event_count, "event_count")
        self.head_event_fingerprint.validated()
        if self.event_count != self.head_sequence + 1:
            raise ObservationError("the anchor's event count must equal its head sequence plus one")


class RunIndexBroken(RuntimeError):
    """The durable run index is missing, reordered, duplicated, or foreign."""


@dataclass(frozen=True)
class RunIndexState:
    """How the durable index stands right now, derived from bytes alone."""

    state: str
    events: tuple[RunIndexEvent, ...]
    anchor: RunIndexAnchor | None
    uncommitted_events: tuple[RunIndexEvent, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "event_count": len(self.events),
            "anchor_head_sequence": None if self.anchor is None else self.anchor.head_sequence,
            "uncommitted_event_count": len(self.uncommitted_events),
        }


class DurableRunIndex:
    """An append-only hash chain of every transition a run made."""

    def __init__(self, store: DurableObjectStore, run_id: str, *, injector: Any | None = None) -> None:
        _require_text(run_id, "run_id", max_bytes=256)
        self._store = store
        self._run_id = run_id
        self._injector = injector or store.injector or NULL_FAULT_INJECTOR

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def store(self) -> DurableObjectStore:
        return self._store

    @staticmethod
    def _object_id(run_id: str, sequence: int) -> str:
        # The sequence is part of the immutable identity, so two different
        # events can never occupy one position and a gap is a missing name.
        return f"{run_id}-{sequence:0{SEQUENCE_WIDTH}d}"

    # -- durable discovery ----------------------------------------------------

    def durable_sequences(self) -> tuple[int, ...]:
        """Every sequence position this run actually has a durable object for.

        The whole directory is scanned.  Counting upward from zero until a name
        is absent -- the previous implementation -- cannot see anything past the
        first gap, which is precisely how a deleted interior event produced a
        shorter chain that verified.
        """

        prefix = f"{RUN_INDEX_OBJECT_KIND}.{self._run_id}-"
        found: list[int] = []
        for name in self._store.committed_names():
            if not name.startswith(prefix) or not name.endswith(".json"):
                continue
            token = name[len(prefix) : -len(".json")]
            if len(token) != SEQUENCE_WIDTH or not token.isdigit():
                raise RunIndexBroken(f"run index object {name} does not carry an exact sequence")
            found.append(int(token))
        if len(set(found)) != len(found):  # pragma: no cover - names are unique on POSIX
            raise RunIndexBroken("a run index sequence is duplicated on disk")
        return tuple(sorted(found))

    def load_anchor(self) -> RunIndexAnchor | None:
        receipt = self._store.inspect(RUN_INDEX_ANCHOR_KIND, self._run_id)
        if receipt.state == "ABSENT":
            return None
        if receipt.state == "CORRUPT":
            raise RunIndexBroken("the run index anchor is not canonical")
        try:
            anchor = RunIndexAnchor.from_dict(self._store.load(RUN_INDEX_ANCHOR_KIND, self._run_id))
        except (CorruptDurableObject, ObservationError, ValueError) as error:
            raise RunIndexBroken(f"the run index anchor did not reconstruct: {error}") from error
        if anchor.run_id != self._run_id:
            raise RunIndexBroken(f"the run index anchor belongs to run {anchor.run_id}")
        return anchor

    def _load_event(self, sequence: int) -> RunIndexEvent:
        object_id = self._object_id(self._run_id, sequence)
        receipt = self._store.inspect(RUN_INDEX_OBJECT_KIND, object_id)
        if receipt.state == "ABSENT":
            raise RunIndexBroken(f"run index event {sequence} is absent")
        if receipt.state == "CORRUPT":
            raise RunIndexBroken(f"run index event {sequence} is not canonical")
        try:
            return RunIndexEvent.from_dict(self._store.load(RUN_INDEX_OBJECT_KIND, object_id))
        except (CorruptDurableObject, ObservationError, ValueError) as error:
            raise RunIndexBroken(f"run index event {sequence} did not reconstruct: {error}") from error

    def state(self) -> RunIndexState:
        """Classify the durable index, failing closed on anything ambiguous."""

        sequences = self.durable_sequences()
        anchor = self.load_anchor()

        if not sequences:
            if anchor is not None:
                raise RunIndexBroken("the run index anchor names a head but no event is durable")
            return RunIndexState(state="EMPTY", events=(), anchor=None, uncommitted_events=())

        # A gap and a surplus position are the same defect seen from two sides:
        # the set of durable positions must be exactly 0..n-1.
        expected = tuple(range(len(sequences)))
        if sequences != expected:
            missing = sorted(set(expected) - set(sequences))
            surplus = sorted(set(sequences) - set(expected))
            raise RunIndexBroken(
                f"the run index positions are not contiguous: missing {missing}, surplus {surplus}"
            )

        events = tuple(self._load_event(sequence) for sequence in sequences)
        self._verify_chain(events)

        top = events[-1]
        # An absent anchor is the committed head of a run that has not committed
        # any event yet, which is exactly the state a crash before the very first
        # head update leaves behind.  It is a position, not a special case.
        head_sequence = -1 if anchor is None else anchor.head_sequence
        if head_sequence > top.sequence:
            # The head outruns the events: the newest event was removed.
            raise RunIndexBroken(
                f"the committed head names sequence {head_sequence} but the chain ends at {top.sequence}"
            )
        if anchor is not None and anchor.head_event_fingerprint != events[head_sequence].record_fingerprint:
            raise RunIndexBroken("the committed head does not match the event it names")
        if head_sequence == top.sequence:
            return RunIndexState(state="COMMITTED", events=events, anchor=anchor, uncommitted_events=())
        if head_sequence == top.sequence - 1:
            # Exactly the window between an event's commit and the head update.
            return RunIndexState(
                state="HEAD_UPDATE_PENDING", events=events, anchor=anchor, uncommitted_events=(top,)
            )
        raise RunIndexBroken(
            f"the committed head at {head_sequence} lags the chain end {top.sequence} by more than one event"
        )

    def load_all(self) -> tuple[RunIndexEvent, ...]:
        """Reconstruct the chain from durable bytes, failing closed on any break."""

        return self.state().events

    def _verify_chain(self, events: tuple[RunIndexEvent, ...]) -> None:
        expected_previous = genesis_fingerprint(self._run_id)
        seen_terminal: set[str] = set()
        proposed: set[str] = set()
        for position, event in enumerate(events):
            if event.run_id != self._run_id:
                # A record from another run cannot be substituted into this one.
                raise RunIndexBroken(f"run index event {position} belongs to run {event.run_id}")
            if event.sequence != position:
                raise RunIndexBroken(
                    f"run index event at position {position} declares sequence {event.sequence}"
                )
            if event.previous_event_fingerprint != expected_previous:
                # Any omission, reordering, or mid-chain substitution breaks the
                # link here rather than being silently absorbed.
                raise RunIndexBroken(f"run index event {position} does not follow its predecessor")
            if event.event_kind == "PROPOSAL_PUBLISHED":
                if event.proposal_id in proposed:
                    raise RunIndexBroken(f"proposal {event.proposal_id} is proposed twice in the run index")
                proposed.add(event.proposal_id)
            else:
                if event.proposal_id not in proposed:
                    raise RunIndexBroken(
                        f"run index event {position} names proposal {event.proposal_id}, which was never indexed as proposed"
                    )
                if event.proposal_id in seen_terminal:
                    raise RunIndexBroken(
                        f"proposal {event.proposal_id} has an event after it was already closed"
                    )
            if event.is_terminal:
                seen_terminal.add(event.proposal_id)
            expected_previous = event.record_fingerprint

    # -- appending ------------------------------------------------------------

    def append_event(
        self,
        *,
        event_kind: str,
        condition_id: str,
        session_id: str,
        turn_id: str,
        proposal_id: str,
        proposal_fingerprint: Fingerprint,
        decision_value: str | None = None,
        decision_permits_effect: bool | None = None,
        outcome: str | None = None,
        effect_crossed_boundary: bool = False,
        effect_receipt_fingerprint: Fingerprint | None = None,
        ledger_entry_fingerprint: Fingerprint | None = None,
        final_reconciliation_fingerprint: Fingerprint | None = None,
        capsule_runtime_manifest_fingerprint: Fingerprint | None = None,
    ) -> RunIndexEvent:
        """Append one link, then advance the committed head to it."""

        state = self.state()
        if state.state == "HEAD_UPDATE_PENDING":
            # A pending head is a recoverable crash state, never a base to build
            # on: the chain is repaired first so the new event follows a
            # committed predecessor.
            raise RunIndexBroken(
                "the run index committed head is pending; recover the index before appending"
            )
        sequence = len(state.events)
        previous = state.events[-1].record_fingerprint if state.events else genesis_fingerprint(self._run_id)
        event = RunIndexEvent.create(
            run_id=self._run_id,
            condition_id=condition_id,
            session_id=session_id,
            turn_id=turn_id,
            sequence=sequence,
            previous_event_fingerprint=previous,
            event_kind=event_kind,
            proposal_id=proposal_id,
            proposal_fingerprint=proposal_fingerprint,
            decision_value=decision_value,
            decision_permits_effect=decision_permits_effect,
            outcome=outcome,
            effect_crossed_boundary=effect_crossed_boundary,
            effect_receipt_fingerprint=effect_receipt_fingerprint,
            ledger_entry_fingerprint=ledger_entry_fingerprint,
            final_reconciliation_fingerprint=final_reconciliation_fingerprint,
            capsule_runtime_manifest_fingerprint=capsule_runtime_manifest_fingerprint,
        )
        # The chain is checked against the new event before it is written, so an
        # event that would break the chain is never durable.
        self._verify_chain(state.events + (event,))

        self._injector.check(FAULT_BEFORE_INDEX_EVENT_PUBLICATION)
        self._store.publish_record(
            object_kind=RUN_INDEX_OBJECT_KIND,
            object_id=self._object_id(self._run_id, sequence),
            record=event,
            fault_point=STAGE_INDEX_EVENT_PUBLICATION,
        )
        self._injector.check(FAULT_AFTER_INDEX_EVENT_BEFORE_ANCHOR)
        self._commit_head(event)
        return event

    def _commit_head(self, event: RunIndexEvent) -> RunIndexAnchor:
        anchor = RunIndexAnchor.create(
            run_id=self._run_id,
            head_sequence=event.sequence,
            event_count=event.sequence + 1,
            head_event_fingerprint=event.record_fingerprint,
        )
        self._store.publish_anchor(
            object_kind=RUN_INDEX_ANCHOR_KIND,
            object_id=self._run_id,
            payload=anchor.to_dict(),
            fault_point=STAGE_INDEX_ANCHOR_UPDATE,
        )
        return anchor

    # -- recovery -------------------------------------------------------------

    def recover_head(self) -> str:
        """Repair a pending committed head without replaying anything.

        The only repair this performs is advancing the anchor onto an event that
        is *already durable and already chained*.  It never writes an event, and
        it never re-executes anything: a crash between an event's commit and the
        head update is a bookkeeping gap, not a lost effect.
        """

        state = self.state()
        if state.state != "HEAD_UPDATE_PENDING":
            return state.state
        self._commit_head(state.uncommitted_events[-1])
        return "COMMITTED"

    # -- reading --------------------------------------------------------------

    def head_anchor(self) -> dict[str, Any]:
        """The exact value an external anti-rollback anchor would pin."""

        anchor = self.load_anchor()
        if anchor is None:
            return {"run_id": self._run_id, "head_sequence": None, "head_event_fingerprint": None}
        return {
            "run_id": self._run_id,
            "head_sequence": anchor.head_sequence,
            "head_event_fingerprint": anchor.head_event_fingerprint.value,
        }

    def head_fingerprint(self) -> Fingerprint:
        events = self.load_all()
        return events[-1].record_fingerprint if events else genesis_fingerprint(self._run_id)

    def head_sequence(self) -> int:
        """The number of durable events, read from bytes, never from memory."""

        return len(self.load_all())

    def indexed_proposal_ids(self) -> tuple[str, ...]:
        """Every proposal this run indexed, in the exact order it proposed them."""

        return tuple(
            event.proposal_id for event in self.load_all() if event.event_kind == "PROPOSAL_PUBLISHED"
        )

    def events_for(self, proposal_id: str) -> tuple[RunIndexEvent, ...]:
        return tuple(event for event in self.load_all() if event.proposal_id == proposal_id)

    def has_event(self, proposal_id: str, event_kind: str) -> bool:
        """Whether this exact transition is already durable for this proposal."""

        return any(event.event_kind == event_kind for event in self.events_for(proposal_id))

    def is_closed(self, proposal_id: str) -> bool:
        return self.terminal_event_for(proposal_id) is not None

    def terminal_event_for(self, proposal_id: str) -> RunIndexEvent | None:
        for event in self.events_for(proposal_id):
            if event.is_terminal:
                return event
        return None

    def open_proposal_ids(self) -> tuple[str, ...]:
        """Proposals that were indexed but never closed by a terminal event."""

        events = self.load_all()
        closed = {event.proposal_id for event in events if event.is_terminal}
        return tuple(
            event.proposal_id
            for event in events
            if event.event_kind == "PROPOSAL_PUBLISHED" and event.proposal_id not in closed
        )

    def verify(self) -> tuple[RunIndexEvent, ...]:
        """Public, explicit re-verification of the durable chain."""

        state = self.state()
        if state.state == "HEAD_UPDATE_PENDING":
            raise RunIndexBroken(
                "the run index committed head is pending; the chain is intact but not committed"
            )
        return state.events


M2_RUN_INDEX_SCHEMAS = {
    RunIndexEvent.SCHEMA_ID: m2_schema_descriptor(
        RunIndexEvent.SCHEMA_ID,
        "RunIndexEvent",
        ("schema_id", "schema_version") + RunIndexEvent.FIELDS + ("record_fingerprint",),
    ),
    RunIndexAnchor.SCHEMA_ID: m2_schema_descriptor(
        RunIndexAnchor.SCHEMA_ID,
        "RunIndexAnchor",
        ("schema_id", "schema_version") + RunIndexAnchor.FIELDS + ("record_fingerprint",),
    ),
}
for _descriptor in M2_RUN_INDEX_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.run_index")


__all__ = [
    "DurableRunIndex",
    "EVENT_KINDS",
    "INDEX_OUTCOMES",
    "INDEX_STATES",
    "M2_RUN_INDEX_SCHEMAS",
    "M2_SCHEMA_VERSION",
    "RUN_INDEX_ANCHOR_KIND",
    "RUN_INDEX_OBJECT_KIND",
    "RunIndexAnchor",
    "RunIndexBroken",
    "RunIndexEvent",
    "RunIndexState",
    "SCHEMA_RUN_INDEX_ANCHOR",
    "SCHEMA_RUN_INDEX_EVENT",
    "SEQUENCE_WIDTH",
    "TERMINAL_EVENT_KINDS",
    "genesis_fingerprint",
]
