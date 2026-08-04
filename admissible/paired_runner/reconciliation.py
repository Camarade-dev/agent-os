"""The one authoritative typed reconciliation path, derived from durable bytes.

Milestone 2 reconciled by asking the object store which names existed.  That is
a presence check, not a reconciliation: an object could be replaced with a
canonical record of the wrong type, from a different run, for a different
proposal, or from an earlier attempt, and the classification would still read
``RECONCILED_COMPLETE``.  Worse, the ledger entry itself *declared*
``RECONCILED_COMPLETE`` before reconciliation had been attempted, so the record
that reconciliation was supposed to check was also the record that asserted the
answer.

This module removes the circularity.  Every referenced object is loaded from
durable bytes, reconstructed as its exact typed class, and cross-checked against
the run, the proposal, the decision, and every other object in the chain.  The
ledger entry is immutable and never predeclares success: it is published in a
``PENDING_VERIFICATION`` state, and a *separate* final reconciliation record --
published only after verification actually succeeded -- binds that exact pending
entry together with the fingerprint of every object that was verified.

Everything here fails closed.  Deletion, substitution, canonical field mutation,
a stale record, a foreign record, a wrong domain, a wrong run, a wrong proposal,
a wrong order, and an unexpected extra object are each a refusal, not a warning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar

from .canonical import Fingerprint, fingerprint
from .durable_store import CorruptDurableObject, DurableObjectStore
from .effect_ledger import LEDGER_OBJECT_KIND, EffectLedgerEntry
from .observation import (
    M2_PREFIX,
    M2_SCHEMA_VERSION,
    EffectReconciliationReport,
    FilesystemObservation,
    GitObservation,
    LifecycleRecord,
    ObservationError,
    ProcessObservation,
    ResourceObservation,
    StreamObservation,
    _decode_fp,
    _decode_strings,
    _encode_fp,
    _encode_strings,
    _M2Record,
    _require_bool,
    _require_member,
    _require_text,
    m2_schema_descriptor,
)
from .schemas import TOOL_EFFECT_CLASSIFICATIONS
from .specification import (
    CanonicalProposal,
    EffectReceipt,
    EffectReservation,
    ExperimentSpecification,
    ModeDecision,
)


SCHEMA_FINAL_RECONCILIATION = f"{M2_PREFIX}.final_reconciliation"
FINAL_RECONCILIATION_OBJECT_KIND = "final-reconciliation"
VERIFIED_OBJECT_SET_DOMAIN = f"{SCHEMA_FINAL_RECONCILIATION}.verified_object_set"

#: The state an immutable ledger entry is published in.  A ledger entry may
#: never assert that reconciliation succeeded; only the separate final
#: reconciliation record, published afterwards, may say that.
LEDGER_PENDING_STATE = "PENDING_VERIFICATION"

#: Object kinds, in the exact causal order the substrate produces them.
OBJECT_KIND_PROPOSAL = "proposal"
OBJECT_KIND_DECISION = "decision"
OBJECT_KIND_RESERVATION = "reservation"
OBJECT_KIND_LIFECYCLE_STARTED = "lifecycle-started"
OBJECT_KIND_FILESYSTEM_BEFORE = "filesystem-before"
OBJECT_KIND_GIT_BEFORE = "git-before"
OBJECT_KIND_FILESYSTEM_AFTER = "filesystem-after"
OBJECT_KIND_GIT_AFTER = "git-after"
OBJECT_KIND_PROCESS = "process-observation"
OBJECT_KIND_STDOUT = "stdout-observation"
OBJECT_KIND_STDERR = "stderr-observation"
OBJECT_KIND_RESOURCE = "resource-observation"
OBJECT_KIND_RECEIPT = "effect-receipt"
OBJECT_KIND_LIFECYCLE_TERMINAL = "lifecycle-terminal"
OBJECT_KIND_RECONCILIATION = "reconciliation"

CAUSAL_OBJECT_ORDER: tuple[str, ...] = (
    OBJECT_KIND_PROPOSAL,
    OBJECT_KIND_DECISION,
    OBJECT_KIND_RESERVATION,
    OBJECT_KIND_LIFECYCLE_STARTED,
    OBJECT_KIND_FILESYSTEM_BEFORE,
    OBJECT_KIND_GIT_BEFORE,
    OBJECT_KIND_FILESYSTEM_AFTER,
    OBJECT_KIND_GIT_AFTER,
    OBJECT_KIND_PROCESS,
    OBJECT_KIND_STDOUT,
    OBJECT_KIND_STDERR,
    OBJECT_KIND_RESOURCE,
    OBJECT_KIND_RECEIPT,
    OBJECT_KIND_LIFECYCLE_TERMINAL,
    OBJECT_KIND_RECONCILIATION,
    LEDGER_OBJECT_KIND,
)

#: The exact typed class each object kind must reconstruct as.  Loading a
#: canonical record of any other type into a slot is a substitution and fails.
OBJECT_KIND_TYPES: dict[str, Any] = {
    OBJECT_KIND_PROPOSAL: CanonicalProposal,
    OBJECT_KIND_DECISION: ModeDecision,
    OBJECT_KIND_RESERVATION: EffectReservation,
    OBJECT_KIND_LIFECYCLE_STARTED: LifecycleRecord,
    OBJECT_KIND_LIFECYCLE_TERMINAL: LifecycleRecord,
    OBJECT_KIND_FILESYSTEM_BEFORE: FilesystemObservation,
    OBJECT_KIND_FILESYSTEM_AFTER: FilesystemObservation,
    OBJECT_KIND_GIT_BEFORE: GitObservation,
    OBJECT_KIND_GIT_AFTER: GitObservation,
    OBJECT_KIND_PROCESS: ProcessObservation,
    OBJECT_KIND_STDOUT: StreamObservation,
    OBJECT_KIND_STDERR: StreamObservation,
    OBJECT_KIND_RESOURCE: ResourceObservation,
    OBJECT_KIND_RECEIPT: EffectReceipt,
    OBJECT_KIND_RECONCILIATION: EffectReconciliationReport,
    LEDGER_OBJECT_KIND: EffectLedgerEntry,
}


class ReconciliationRefused(Exception):
    """The durable chain does not reconcile, so nothing may be claimed."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _refuse(code: str, detail: str) -> "ReconciliationRefused":
    return ReconciliationRefused(code, detail)


def expected_object_kinds(
    *,
    decision_permits_effect: bool,
    tool_name: str,
    lifecycle_terminal_present: bool,
    effect_started: bool = True,
) -> tuple[str, ...]:
    """The exact object set this effect must have produced -- no more, no less.

    The set is a function of the decision, the tool, and the effect class, so an
    object that is missing *and* an object that should not exist are both
    detected.  A run-command chain that carries no process observation, and a
    read-only chain that carries one, are equally wrong.
    """

    if not decision_permits_effect:
        return (
            OBJECT_KIND_DECISION,
            OBJECT_KIND_PROPOSAL,
            OBJECT_KIND_RECEIPT,
            OBJECT_KIND_RECONCILIATION,
        )

    if not effect_started:
        # The decision permitted an effect and a reservation exists, but the
        # physical preconditions were refused before any STARTED record was
        # published, so no lifecycle or observation object may exist.
        return tuple(
            sorted(
                (
                    OBJECT_KIND_PROPOSAL,
                    OBJECT_KIND_DECISION,
                    OBJECT_KIND_RESERVATION,
                    OBJECT_KIND_RECEIPT,
                    OBJECT_KIND_RECONCILIATION,
                )
            )
        )

    kinds = [
        OBJECT_KIND_PROPOSAL,
        OBJECT_KIND_DECISION,
        OBJECT_KIND_RESERVATION,
        OBJECT_KIND_LIFECYCLE_STARTED,
        OBJECT_KIND_FILESYSTEM_BEFORE,
        OBJECT_KIND_GIT_BEFORE,
        OBJECT_KIND_FILESYSTEM_AFTER,
        OBJECT_KIND_GIT_AFTER,
        OBJECT_KIND_RECEIPT,
        OBJECT_KIND_RECONCILIATION,
    ]
    if TOOL_EFFECT_CLASSIFICATIONS[tool_name] == "PROCESS_EXECUTION":
        kinds += [
            OBJECT_KIND_PROCESS,
            OBJECT_KIND_STDOUT,
            OBJECT_KIND_STDERR,
            OBJECT_KIND_RESOURCE,
        ]
    if lifecycle_terminal_present:
        kinds += [OBJECT_KIND_LIFECYCLE_TERMINAL, LEDGER_OBJECT_KIND]
    return tuple(sorted(kinds))


@dataclass(frozen=True)
class VerifiedObject:
    """One durable object that was loaded, typed, and cross-checked."""

    object_kind: str
    object_id: str
    record_fingerprint: str
    content_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "record_fingerprint": self.record_fingerprint,
            "content_fingerprint": self.content_fingerprint,
        }


@dataclass(frozen=True)
class FinalReconciliation(_M2Record):
    """The separate, non-circular record that reconciliation actually passed.

    It is published only after every referenced object has been verified, and it
    binds the exact immutable pending ledger entry it verified together with the
    complete set of verified object fingerprints.  Because the ledger entry
    itself never claims success, this record cannot be satisfied by the entry it
    is checking.
    """

    SCHEMA_ID: ClassVar[str] = SCHEMA_FINAL_RECONCILIATION
    LABEL: ClassVar[str] = "final reconciliation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "run_id",
        "proposal_id",
        "condition_id",
        "tool_name",
        "effect_classification",
        "decision_value",
        "receipt_status",
        "verified",
        "verdict",
        "pending_ledger_entry_fingerprint",
        "experiment_specification_fingerprint",
        "verified_object_kinds",
        "verified_object_set_fingerprint",
        "refusal_code",
        "reconciliation_note",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "pending_ledger_entry_fingerprint": _encode_fp,
        "experiment_specification_fingerprint": _encode_fp,
        "verified_object_kinds": _encode_strings,
        "verified_object_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "pending_ledger_entry_fingerprint": _decode_fp,
        "experiment_specification_fingerprint": _decode_fp,
        "verified_object_kinds": _decode_strings,
        "verified_object_set_fingerprint": _decode_fp,
    }

    run_id: str
    proposal_id: str
    condition_id: str
    tool_name: str
    effect_classification: str
    decision_value: str
    receipt_status: str
    verified: bool
    verdict: str
    pending_ledger_entry_fingerprint: Fingerprint
    experiment_specification_fingerprint: Fingerprint
    verified_object_kinds: tuple[str, ...]
    verified_object_set_fingerprint: Fingerprint
    refusal_code: str | None
    reconciliation_note: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "FinalReconciliation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        for name in ("run_id", "proposal_id", "condition_id", "tool_name", "decision_value", "receipt_status", "verdict"):
            _require_text(getattr(self, name), name, max_bytes=256)
        _require_text(self.reconciliation_note, "reconciliation_note", max_bytes=2048)
        _require_bool(self.verified, "verified")
        _require_member(self.condition_id, ("DIRECT", "GOVERNED"), "condition_id")
        self.pending_ledger_entry_fingerprint.validated()
        self.experiment_specification_fingerprint.validated()
        self.verified_object_set_fingerprint.validated()
        _encode_strings(self.verified_object_kinds)
        if self.refusal_code is not None:
            _require_text(self.refusal_code, "refusal_code", max_bytes=128)
        if self.verified and self.refusal_code is not None:
            raise ObservationError("a verified reconciliation carries no refusal code")
        if not self.verified and self.refusal_code is None:
            raise ObservationError("an unverified reconciliation must name its refusal")


def verified_object_set_fingerprint(objects: tuple[VerifiedObject, ...]) -> Fingerprint:
    return fingerprint(
        {"objects": [item.to_dict() for item in sorted(objects, key=lambda o: (o.object_kind, o.object_id))]},
        domain=VERIFIED_OBJECT_SET_DOMAIN,
    )


class TypedChainVerifier:
    """Reconstructs and cross-checks one effect's entire durable chain."""

    def __init__(
        self,
        store: DurableObjectStore,
        *,
        run_id: str,
        proposal_id: str,
        specification: ExperimentSpecification | None = None,
        specification_fingerprint: Fingerprint | None = None,
    ) -> None:
        self._store = store
        self._run_id = run_id
        self._proposal_id = proposal_id
        self._specification = specification
        if specification is not None:
            self._specification_fingerprint = specification.specification_fingerprint
        elif specification_fingerprint is not None:
            # An externally supplied exact specification fingerprint is accepted
            # in place of the specification object itself, but nothing weaker.
            self._specification_fingerprint = specification_fingerprint.validated()
        else:
            raise _refuse(
                "SPECIFICATION_UNAVAILABLE",
                "reconciliation requires the exact experiment specification or its exact fingerprint",
            )
        self._verified: list[VerifiedObject] = []

    # -- primitive loading ---------------------------------------------------

    def _load_typed(self, object_kind: str, *, object_id: str | None = None) -> Any:
        identifier = object_id or self._proposal_id
        receipt = self._store.inspect(object_kind, identifier)
        if receipt.state == "ABSENT":
            raise _refuse("OBJECT_ABSENT", f"{object_kind} for {identifier} is not durable")
        if receipt.state == "CORRUPT":
            raise _refuse("OBJECT_CORRUPT", f"{object_kind} for {identifier} is not canonical")
        try:
            payload = self._store.load(object_kind, identifier)
        except CorruptDurableObject as error:
            raise _refuse("OBJECT_CORRUPT", str(error)) from error

        expected_type = OBJECT_KIND_TYPES[object_kind]
        try:
            record = expected_type.from_dict(payload)
        except Exception as error:  # noqa: BLE001 - any typed failure is a refusal
            # A canonical record of the wrong type, or one whose canonical
            # fields were mutated, cannot reconstruct here.  Canonical JSON is
            # not evidence of anything on its own.
            raise _refuse(
                "OBJECT_NOT_THE_EXPECTED_TYPE",
                f"{object_kind} for {identifier} did not reconstruct as {expected_type.__name__}: {error}",
            ) from error

        self._verified.append(
            VerifiedObject(
                object_kind=object_kind,
                object_id=identifier,
                record_fingerprint=_record_fingerprint_value(record),
                content_fingerprint=receipt.content_fingerprint.value,
            )
        )
        return record

    # -- the authoritative verification --------------------------------------

    def verify(self) -> tuple[dict[str, Any], tuple[VerifiedObject, ...]]:
        """Verify the full typed chain and return the reconstructed objects."""

        chain: dict[str, Any] = {}

        proposal = self._load_typed(OBJECT_KIND_PROPOSAL)
        chain[OBJECT_KIND_PROPOSAL] = proposal
        # Wrong run, wrong proposal, and a foreign specification are each fatal.
        if proposal.proposal_id != self._proposal_id:
            raise _refuse("WRONG_PROPOSAL", "the durable proposal names a different proposal id")
        if proposal.run_identity.run_id != self._run_id:
            raise _refuse("WRONG_RUN", "the durable proposal belongs to a different run")
        if proposal.experiment_specification_fingerprint != self._specification_fingerprint:
            raise _refuse(
                "WRONG_SPECIFICATION",
                "the durable proposal is bound to a different experiment specification",
            )
        if self._specification is not None:
            try:
                proposal.validate_for_specification(self._specification)
            except Exception as error:  # noqa: BLE001
                raise _refuse("PROPOSAL_SPECIFICATION_MISMATCH", str(error)) from error

        decision = self._load_typed(OBJECT_KIND_DECISION)
        chain[OBJECT_KIND_DECISION] = decision
        try:
            decision.validate_for_proposal(proposal)
        except Exception as error:  # noqa: BLE001
            raise _refuse("DECISION_DOES_NOT_BIND_PROPOSAL", str(error)) from error

        receipt = self._load_typed(OBJECT_KIND_RECEIPT)
        chain[OBJECT_KIND_RECEIPT] = receipt

        permits = decision.permits_effect
        reservation = None
        if permits:
            reservation = self._load_typed(OBJECT_KIND_RESERVATION)
            chain[OBJECT_KIND_RESERVATION] = reservation
            try:
                reservation.validate_for_decision(self._specification, proposal, decision) if self._specification else None
            except Exception as error:  # noqa: BLE001
                raise _refuse("RESERVATION_DOES_NOT_BIND_DECISION", str(error)) from error
            if reservation.proposal_fingerprint != proposal.proposal_fingerprint:
                raise _refuse("RESERVATION_BINDS_ANOTHER_PROPOSAL", "reservation proposal fingerprint mismatch")

            started_durable = (
                self._store.inspect(OBJECT_KIND_LIFECYCLE_STARTED, self._proposal_id).state != "ABSENT"
            )
        if permits and started_durable:
            started = self._load_typed(OBJECT_KIND_LIFECYCLE_STARTED)
            chain[OBJECT_KIND_LIFECYCLE_STARTED] = started
            self._check_lifecycle(started, "STARTED", proposal, reservation)

            for kind in (
                OBJECT_KIND_FILESYSTEM_BEFORE,
                OBJECT_KIND_GIT_BEFORE,
                OBJECT_KIND_FILESYSTEM_AFTER,
                OBJECT_KIND_GIT_AFTER,
            ):
                chain[kind] = self._load_typed(kind)
            self._check_phase(chain[OBJECT_KIND_FILESYSTEM_BEFORE], "BEFORE_EFFECT", OBJECT_KIND_FILESYSTEM_BEFORE)
            self._check_phase(chain[OBJECT_KIND_FILESYSTEM_AFTER], "AFTER_EFFECT", OBJECT_KIND_FILESYSTEM_AFTER)
            self._check_phase(chain[OBJECT_KIND_GIT_BEFORE], "BEFORE_EFFECT", OBJECT_KIND_GIT_BEFORE)
            self._check_phase(chain[OBJECT_KIND_GIT_AFTER], "AFTER_EFFECT", OBJECT_KIND_GIT_AFTER)

            if TOOL_EFFECT_CLASSIFICATIONS[proposal.tool_name] == "PROCESS_EXECUTION":
                for kind in (OBJECT_KIND_PROCESS, OBJECT_KIND_STDOUT, OBJECT_KIND_STDERR, OBJECT_KIND_RESOURCE):
                    chain[kind] = self._load_typed(kind)
                if chain[OBJECT_KIND_STDOUT].stream_name != "stdout":
                    raise _refuse("STREAM_SUBSTITUTED", "the stdout slot does not hold the stdout stream")
                if chain[OBJECT_KIND_STDERR].stream_name != "stderr":
                    raise _refuse("STREAM_SUBSTITUTED", "the stderr slot does not hold the stderr stream")

        try:
            receipt.validate_for_causal_chain(
                specification=self._specification,
                proposal=proposal,
                decision=decision,
                reservation=reservation,
            ) if self._specification else None
        except Exception as error:  # noqa: BLE001
            raise _refuse("RECEIPT_DOES_NOT_CLOSE_THE_CHAIN", str(error)) from error

        started_present = (
            permits
            and self._store.inspect(OBJECT_KIND_LIFECYCLE_STARTED, self._proposal_id).state != "ABSENT"
        )
        terminal_present = self._store.inspect(OBJECT_KIND_LIFECYCLE_TERMINAL, self._proposal_id).state != "ABSENT"
        if terminal_present:
            terminal = self._load_typed(OBJECT_KIND_LIFECYCLE_TERMINAL)
            chain[OBJECT_KIND_LIFECYCLE_TERMINAL] = terminal
            self._check_lifecycle(terminal, "TERMINAL", proposal, reservation)
            if terminal.receipt_status != receipt.status:
                raise _refuse(
                    "LIFECYCLE_CONTRADICTS_RECEIPT",
                    "the terminal lifecycle status differs from the receipt status",
                )
            # Causal order is checked, not assumed: a terminal record that
            # precedes its own STARTED record is a reordering.
            started = chain.get(OBJECT_KIND_LIFECYCLE_STARTED)
            if started is not None and terminal.monotonic_ns < started.monotonic_ns:
                raise _refuse("WRONG_ORDER", "the terminal lifecycle record precedes the STARTED record")

            entry = self._load_typed(LEDGER_OBJECT_KIND)
            chain[LEDGER_OBJECT_KIND] = entry
            self._check_ledger_entry(entry, chain)

        # The reconciliation report is itself a persisted referenced object, so
        # deleting or corrupting it must fail the chain like any other.
        report = self._load_typed(OBJECT_KIND_RECONCILIATION)
        chain[OBJECT_KIND_RECONCILIATION] = report
        if report.run_id != self._run_id:
            raise _refuse("WRONG_RUN", "the reconciliation report belongs to another run")
        if report.proposal_id != self._proposal_id:
            raise _refuse("WRONG_PROPOSAL", "the reconciliation report names another proposal")

        self._check_object_set(
            decision_permits_effect=permits,
            tool_name=proposal.tool_name,
            lifecycle_terminal_present=terminal_present,
            effect_started=started_present,
        )
        return chain, tuple(self._verified)

    # -- individual cross-checks ---------------------------------------------

    def _check_phase(self, record: Any, expected: str, kind: str) -> None:
        if record.phase != expected:
            raise _refuse(
                "OBSERVATION_PHASE_SUBSTITUTED",
                f"{kind} holds a {record.phase} observation instead of {expected}",
            )

    def _check_lifecycle(self, record: Any, kind: str, proposal: Any, reservation: Any) -> None:
        if record.kind != kind:
            raise _refuse("LIFECYCLE_SUBSTITUTED", f"expected a {kind} lifecycle record, found {record.kind}")
        if record.run_id != self._run_id:
            raise _refuse("WRONG_RUN", f"the {kind} lifecycle record belongs to another run")
        if record.proposal_id != self._proposal_id:
            raise _refuse("WRONG_PROPOSAL", f"the {kind} lifecycle record names another proposal")
        if record.proposal_fingerprint != proposal.proposal_fingerprint:
            raise _refuse("STALE_RECORD", f"the {kind} lifecycle record binds a different proposal version")
        if reservation is not None and record.reservation_fingerprint != reservation.reservation_fingerprint:
            raise _refuse("STALE_RECORD", f"the {kind} lifecycle record binds a different reservation")

    def _check_ledger_entry(self, entry: EffectLedgerEntry, chain: dict[str, Any]) -> None:
        """Compare every ledger field with the object it claims to describe."""

        proposal = chain[OBJECT_KIND_PROPOSAL]
        decision = chain[OBJECT_KIND_DECISION]
        receipt = chain[OBJECT_KIND_RECEIPT]
        reservation = chain.get(OBJECT_KIND_RESERVATION)
        started = chain.get(OBJECT_KIND_LIFECYCLE_STARTED)

        # A ledger entry may never assert that it reconciled.  That claim lives
        # only in the separate final reconciliation record.
        if entry.final_reconciliation_state != LEDGER_PENDING_STATE:
            raise _refuse(
                "LEDGER_PREDECLARES_RECONCILIATION",
                f"a ledger entry must be published as {LEDGER_PENDING_STATE}, not "
                f"{entry.final_reconciliation_state}",
            )

        comparisons: tuple[tuple[str, Any, Any], ...] = (
            ("run_id", entry.run_id, proposal.run_identity.run_id),
            ("proposal_id", entry.proposal_id, proposal.proposal_id),
            ("condition_id", entry.condition_id, proposal.condition.condition_id),
            ("session_id", entry.session_id, proposal.session_identity.session_id),
            ("proposal_fingerprint", entry.proposal_fingerprint, proposal.proposal_fingerprint),
            ("decision_fingerprint", entry.decision_fingerprint, decision.decision_fingerprint),
            ("decision_value", entry.decision_value, decision.decision),
            ("tool_name", entry.tool_name, proposal.tool_name),
            ("effect_classification", entry.effect_classification, receipt.effect_classification),
            ("tool_request_fingerprint", entry.tool_request_fingerprint, proposal.tool_request.request_fingerprint),
            ("effect_receipt_fingerprint", entry.effect_receipt_fingerprint, receipt.receipt_fingerprint),
            (
                "experiment_specification_fingerprint",
                entry.experiment_specification_fingerprint,
                self._specification_fingerprint,
            ),
        )
        for field, claimed, actual in comparisons:
            if claimed != actual:
                raise _refuse(
                    "LEDGER_FIELD_CONTRADICTS_OBJECT",
                    f"ledger {field} does not match the reconstructed durable object",
                )

        if reservation is not None:
            if entry.reservation_id != reservation.reservation_id:
                raise _refuse("LEDGER_FIELD_CONTRADICTS_OBJECT", "ledger reservation_id mismatch")
            if entry.reservation_fingerprint != reservation.reservation_fingerprint:
                raise _refuse("LEDGER_FIELD_CONTRADICTS_OBJECT", "ledger reservation_fingerprint mismatch")
        elif entry.reservation_id is not None:
            raise _refuse("LEDGER_FIELD_CONTRADICTS_OBJECT", "ledger names a reservation that is not durable")

        expected_result = None if receipt.tool_result is None else receipt.tool_result.result_fingerprint
        if entry.tool_result_fingerprint != expected_result:
            raise _refuse("LEDGER_FIELD_CONTRADICTS_OBJECT", "ledger tool_result_fingerprint mismatch")

        if started is not None:
            expected_lifecycle = (started.record_fingerprint.value, receipt.receipt_fingerprint.value)
            if tuple(entry.lifecycle_receipt_fingerprints) != expected_lifecycle:
                raise _refuse(
                    "LEDGER_FIELD_CONTRADICTS_OBJECT",
                    "ledger lifecycle receipt fingerprints do not match the durable lifecycle chain",
                )

        for field, kind in (
            ("filesystem_observation_before_fingerprint", OBJECT_KIND_FILESYSTEM_BEFORE),
            ("filesystem_observation_after_fingerprint", OBJECT_KIND_FILESYSTEM_AFTER),
            ("git_observation_before_fingerprint", OBJECT_KIND_GIT_BEFORE),
            ("git_observation_after_fingerprint", OBJECT_KIND_GIT_AFTER),
            ("process_observation_fingerprint", OBJECT_KIND_PROCESS),
            ("stdout_observation_fingerprint", OBJECT_KIND_STDOUT),
            ("stderr_observation_fingerprint", OBJECT_KIND_STDERR),
            ("resource_observation_fingerprint", OBJECT_KIND_RESOURCE),
        ):
            claimed = getattr(entry, field)
            observed = chain.get(kind)
            actual = None if observed is None else observed.record_fingerprint
            if claimed != actual:
                raise _refuse(
                    "LEDGER_FIELD_CONTRADICTS_OBJECT",
                    f"ledger {field} does not match the reconstructed durable object",
                )

    def _check_object_set(
        self,
        *,
        decision_permits_effect: bool,
        tool_name: str,
        lifecycle_terminal_present: bool,
        effect_started: bool = True,
    ) -> None:
        """Require the exact expected object set -- no omission, no surplus."""

        expected = set(
            expected_object_kinds(
                decision_permits_effect=decision_permits_effect,
                tool_name=tool_name,
                lifecycle_terminal_present=lifecycle_terminal_present,
                effect_started=effect_started,
            )
        )
        present = {
            kind
            for kind in CAUSAL_OBJECT_ORDER
            if self._store.inspect(kind, self._proposal_id).state != "ABSENT"
        }
        missing = sorted(expected - present)
        if missing:
            raise _refuse("EXPECTED_OBJECT_ABSENT", f"the chain is missing {missing}")
        surplus = sorted(present - expected)
        if surplus:
            raise _refuse("UNEXPECTED_OBJECT_PRESENT", f"the chain carries unexpected objects {surplus}")


def _record_fingerprint_value(record: Any) -> str:
    for attribute in ("record_fingerprint", "receipt_fingerprint", "proposal_fingerprint", "decision_fingerprint", "reservation_fingerprint"):
        value = getattr(record, attribute, None)
        if isinstance(value, Fingerprint):
            return value.value
    raise _refuse("OBJECT_HAS_NO_FINGERPRINT", f"{type(record).__name__} exposes no record fingerprint")


def reconcile_typed_chain(
    store: DurableObjectStore,
    *,
    run_id: str,
    proposal_id: str,
    specification: ExperimentSpecification | None = None,
    specification_fingerprint: Fingerprint | None = None,
) -> FinalReconciliation:
    """The one authoritative reconciliation.  It fails closed on any defect."""

    try:
        verifier = TypedChainVerifier(
            store,
            run_id=run_id,
            proposal_id=proposal_id,
            specification=specification,
            specification_fingerprint=specification_fingerprint,
        )
        chain, verified = verifier.verify()
    except ReconciliationRefused as refusal:
        return _unverified(run_id, proposal_id, refusal)

    proposal = chain[OBJECT_KIND_PROPOSAL]
    decision = chain[OBJECT_KIND_DECISION]
    receipt = chain[OBJECT_KIND_RECEIPT]
    entry = chain.get(LEDGER_OBJECT_KIND)
    pending_fingerprint = (
        entry.record_fingerprint
        if entry is not None
        else fingerprint({"no_ledger_entry": proposal_id}, domain=f"{SCHEMA_FINAL_RECONCILIATION}.absent_entry")
    )
    return FinalReconciliation.create(
        run_id=run_id,
        proposal_id=proposal_id,
        condition_id=proposal.condition.condition_id,
        tool_name=proposal.tool_name,
        effect_classification=receipt.effect_classification,
        decision_value=decision.decision,
        receipt_status=receipt.status,
        verified=True,
        verdict="TYPED_CHAIN_VERIFIED",
        pending_ledger_entry_fingerprint=pending_fingerprint,
        experiment_specification_fingerprint=proposal.experiment_specification_fingerprint,
        verified_object_kinds=tuple(sorted({item.object_kind for item in verified})),
        verified_object_set_fingerprint=verified_object_set_fingerprint(verified),
        refusal_code=None,
        reconciliation_note=(
            "every referenced durable object was loaded, reconstructed as its exact typed class, "
            "and cross-checked against the run, the proposal, the decision, and the ledger entry"
        ),
    )


def _unverified(run_id: str, proposal_id: str, refusal: ReconciliationRefused) -> FinalReconciliation:
    absent = fingerprint({"unverified": proposal_id}, domain=f"{SCHEMA_FINAL_RECONCILIATION}.absent_entry")
    return FinalReconciliation.create(
        run_id=run_id,
        proposal_id=proposal_id,
        condition_id="DIRECT",
        tool_name="unknown",
        effect_classification="READ_ONLY",
        decision_value="UNVERIFIED",
        receipt_status="UNVERIFIED",
        verified=False,
        verdict="TYPED_CHAIN_REFUSED",
        pending_ledger_entry_fingerprint=absent,
        experiment_specification_fingerprint=absent,
        verified_object_kinds=(),
        verified_object_set_fingerprint=verified_object_set_fingerprint(()),
        refusal_code=refusal.code,
        reconciliation_note=refusal.detail[:2000],
    )


M2_RECONCILIATION_SCHEMAS = {
    FinalReconciliation.SCHEMA_ID: m2_schema_descriptor(
        FinalReconciliation.SCHEMA_ID,
        "FinalReconciliation",
        ("schema_id", "schema_version") + FinalReconciliation.FIELDS + ("record_fingerprint",),
    )
}
for _descriptor in M2_RECONCILIATION_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.reconciliation")


__all__ = [
    "CAUSAL_OBJECT_ORDER",
    "FINAL_RECONCILIATION_OBJECT_KIND",
    "FinalReconciliation",
    "LEDGER_PENDING_STATE",
    "M2_RECONCILIATION_SCHEMAS",
    "M2_SCHEMA_VERSION",
    "OBJECT_KIND_TYPES",
    "ReconciliationRefused",
    "SCHEMA_FINAL_RECONCILIATION",
    "TypedChainVerifier",
    "VerifiedObject",
    "expected_object_kinds",
    "reconcile_typed_chain",
    "verified_object_set_fingerprint",
]
