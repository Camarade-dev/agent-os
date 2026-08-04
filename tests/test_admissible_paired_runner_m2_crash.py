"""Crash and corruption tests for the Milestone 2 shared effect substrate.

Every one of the thirteen declared fault-injection points is replayed against a
disposable workspace, and every persisted object class is corrupted twice — once
by flipping a committed byte and once by mutating a single canonical field — to
prove that reconstruction fails closed.

The expected outcome of each fault point is declared literally in this file.  No
expectation is read back from the implementation being tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _paired_runner_m2_fixtures import (  # noqa: E402
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
)
from admissible.paired_runner.canonical import canonical_bytes  # noqa: E402
from admissible.paired_runner.durable_store import (  # noqa: E402
    FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT,
    FAULT_AFTER_PROPOSAL_FSYNC_BEFORE_RENAME,
    FAULT_AFTER_PROPOSAL_PUBLICATION,
    FAULT_AFTER_PROPOSAL_RENAME_BEFORE_DIR_FSYNC,
    FAULT_AFTER_RESERVATION_PUBLICATION,
    FAULT_AFTER_STARTED_BEFORE_EFFECT,
    FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION,
    FAULT_BEFORE_PROPOSAL_PUBLICATION,
    FAULT_BEFORE_RESERVATION_PUBLICATION,
    FAULT_BEFORE_STARTED_PUBLICATION,
    FAULT_DURING_PROPOSAL_TEMP_WRITE,
    FAULT_DURING_RECONCILIATION_PUBLICATION,
    FAULT_DURING_TERMINAL_RECEIPT_PUBLICATION,
    FAULT_POINTS,
    DurableObjectStore,
    FaultInjector,
    InjectedFault,
)
from admissible.paired_runner.effect_ledger import (  # noqa: E402
    LEDGER_OBJECT_KIND,
    EffectLedgerEntry,
    RunEffectLedger,
)
from admissible.paired_runner.effects import (  # noqa: E402
    OBJECT_KIND_LIFECYCLE_STARTED,
    OBJECT_KIND_PROPOSAL,
    OBJECT_KIND_RECEIPT,
    OBJECT_KIND_RESERVATION,
    AmbiguousEffectRefused,
    SharedEffectSubstrate,
    WorkspaceBinding,
    reconcile_effect,
)
from admissible.paired_runner.observation import observation_from_dict  # noqa: E402
from admissible.paired_runner.specification import (  # noqa: E402
    CanonicalProposal,
    EffectReceipt,
    EffectReservation,
    ModeDecision,
)
from admissible.paired_runner.tool_schemas import WriteFileRequest  # noqa: E402


PROPOSAL_ID = "proposal-1"
TARGET_FILE = "mutated.txt"
TARGET_CONTENT = "durable effect bytes\n"


@dataclass(frozen=True)
class CrashExpectation:
    """The literally declared expectation for one fault-injection point."""

    point: str
    proposal_durable: bool
    reservation_durable: bool
    started_durable: bool
    receipt_durable: bool
    ledger_durable: bool
    effect_invocations: int
    classification: str
    effect_may_have_occurred: bool
    partial_publication_expected: bool
    workspace_mutated: bool


CRASH_MATRIX: tuple[CrashExpectation, ...] = (
    CrashExpectation(
        FAULT_BEFORE_PROPOSAL_PUBLICATION,
        False, False, False, False, False, 0, "NO_DURABLE_STATE", False, False, False,
    ),
    CrashExpectation(
        FAULT_DURING_PROPOSAL_TEMP_WRITE,
        False, False, False, False, False, 0, "NO_DURABLE_STATE", False, True, False,
    ),
    CrashExpectation(
        FAULT_AFTER_PROPOSAL_FSYNC_BEFORE_RENAME,
        False, False, False, False, False, 0, "NO_DURABLE_STATE", False, True, False,
    ),
    CrashExpectation(
        FAULT_AFTER_PROPOSAL_RENAME_BEFORE_DIR_FSYNC,
        True, False, False, False, False, 0, "PROPOSAL_ONLY_NO_EFFECT_POSSIBLE", False, True, False,
    ),
    CrashExpectation(
        FAULT_AFTER_PROPOSAL_PUBLICATION,
        True, False, False, False, False, 0, "PROPOSAL_ONLY_NO_EFFECT_POSSIBLE", False, False, False,
    ),
    CrashExpectation(
        FAULT_BEFORE_RESERVATION_PUBLICATION,
        True, False, False, False, False, 0, "PROPOSAL_ONLY_NO_EFFECT_POSSIBLE", False, False, False,
    ),
    CrashExpectation(
        FAULT_AFTER_RESERVATION_PUBLICATION,
        True, True, False, False, False, 0, "RESERVED_NO_EFFECT_POSSIBLE", False, False, False,
    ),
    CrashExpectation(
        FAULT_BEFORE_STARTED_PUBLICATION,
        True, True, False, False, False, 0, "RESERVED_NO_EFFECT_POSSIBLE", False, False, False,
    ),
    CrashExpectation(
        FAULT_AFTER_STARTED_BEFORE_EFFECT,
        True, True, True, False, False, 0,
        "STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION", True, False, False,
    ),
    CrashExpectation(
        FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT,
        True, True, True, False, False, 1,
        "STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION", True, False, True,
    ),
    CrashExpectation(
        FAULT_DURING_TERMINAL_RECEIPT_PUBLICATION,
        True, True, True, False, False, 1,
        "STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION", True, True, True,
    ),
    CrashExpectation(
        FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION,
        True, True, True, True, False, 1,
        "TERMINAL_RECEIPT_DURABLE_RECONCILIATION_INCOMPLETE", True, False, True,
    ),
    CrashExpectation(
        FAULT_DURING_RECONCILIATION_PUBLICATION,
        True, True, True, True, False, 1,
        "TERMINAL_RECEIPT_DURABLE_RECONCILIATION_INCOMPLETE", True, True, True,
    ),
)


class _CrashHarness:
    def __init__(self, point: str) -> None:
        self.specification = build_specification("GOVERNED", run_id="run-crash")
        self.disposable = DisposableWorkspace()
        self.injector = FaultInjector({point})
        self.binding = WorkspaceBinding.bind(self.disposable.workspace, self.specification)
        self.store = DurableObjectStore(self.disposable.store_root, injector=self.injector)
        self.substrate = SharedEffectSubstrate(
            binding=self.binding,
            store=self.store,
            ledger=RunEffectLedger("run-crash"),
            injector=self.injector,
        )
        self.request = WriteFileRequest.create(
            tool_grammar_fingerprint=self.specification.tool_grammar.grammar_fingerprint,
            path=TARGET_FILE,
            content=TARGET_CONTENT,
        )
        self.proposal = build_proposal(self.specification, self.request, proposal_id=PROPOSAL_ID)
        self.decision = decision_for(self.proposal)

    def execute(self):
        return self.substrate.execute(
            specification=self.specification,
            proposal=self.proposal,
            decision=self.decision,
            reservation_id="reservation-1",
            receipt_id="receipt-1",
        )

    def close(self) -> None:
        self.binding.close()
        self.disposable.close()


class CrashMatrixTests(unittest.TestCase):
    """Replay every declared fault point and assert the durable consequences."""

    def test_every_declared_fault_point_is_covered_exactly_once(self) -> None:
        declared = tuple(expectation.point for expectation in CRASH_MATRIX)
        self.assertEqual(len(set(declared)), len(declared))
        self.assertEqual(set(declared), set(FAULT_POINTS))
        self.assertEqual(len(CRASH_MATRIX), 13)

    def test_fault_points(self) -> None:
        for expectation in CRASH_MATRIX:
            with self.subTest(point=expectation.point):
                self._replay(expectation)

    def _replay(self, expectation: CrashExpectation) -> None:
        harness = _CrashHarness(expectation.point)
        self.addCleanup(harness.close)
        with self.assertRaises(InjectedFault) as raised:
            harness.execute()
        self.assertEqual(raised.exception.point, expectation.point)

        store = harness.store
        self.assertEqual(
            store.inspect(OBJECT_KIND_PROPOSAL, PROPOSAL_ID).durable, expectation.proposal_durable
        )
        self.assertEqual(
            store.inspect(OBJECT_KIND_RESERVATION, PROPOSAL_ID).durable, expectation.reservation_durable
        )
        self.assertEqual(
            store.inspect(OBJECT_KIND_LIFECYCLE_STARTED, PROPOSAL_ID).durable, expectation.started_durable
        )
        self.assertEqual(store.inspect(OBJECT_KIND_RECEIPT, PROPOSAL_ID).durable, expectation.receipt_durable)
        self.assertEqual(store.inspect(LEDGER_OBJECT_KIND, PROPOSAL_ID).durable, expectation.ledger_durable)
        self.assertEqual(harness.substrate.effect_invocation_count, expectation.effect_invocations)
        self.assertEqual(
            (harness.disposable.workspace / TARGET_FILE).exists(), expectation.workspace_mutated
        )

        report = reconcile_effect(store, run_id="run-crash", proposal_id=PROPOSAL_ID)
        self.assertEqual(report.classification, expectation.classification)
        self.assertEqual(report.effect_may_have_occurred, expectation.effect_may_have_occurred)
        # An effect that may have occurred is never automatically replayed.
        self.assertFalse(report.replay_permitted)
        self.assertEqual(bool(report.partial_publications), expectation.partial_publication_expected)
        for temporary in report.partial_publications:
            self.assertTrue(temporary.startswith(".tmp-publication-"))
            # A temporary file is never mistaken for a committed object.
            self.assertNotIn(temporary, store.committed_names())
        self.assertEqual(report.corrupt_objects, ())

        # No fault point may leave a receipt claiming completion.
        if expectation.receipt_durable:
            receipt = EffectReceipt.from_dict(store.load(OBJECT_KIND_RECEIPT, PROPOSAL_ID))
            self.assertEqual(receipt.status, "COMPLETED")
            self.assertIsNone(receipt.task_acceptance)
            # A durable receipt is only reachable after the effect completed and
            # the reconciliation is still explicitly incomplete.
            self.assertEqual(report.classification, "TERMINAL_RECEIPT_DURABLE_RECONCILIATION_INCOMPLETE")
        else:
            self.assertEqual(store.inspect(OBJECT_KIND_RECEIPT, PROPOSAL_ID).state, "ABSENT")

    def test_a_started_effect_is_never_replayed_after_a_crash(self) -> None:
        harness = _CrashHarness(FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT)
        self.addCleanup(harness.close)
        with self.assertRaises(InjectedFault):
            harness.execute()
        self.assertEqual(harness.substrate.effect_invocation_count, 1)
        first_bytes = (harness.disposable.workspace / TARGET_FILE).read_bytes()

        # A fresh controller restarts from durable bytes alone.
        recovered = SharedEffectSubstrate(
            binding=harness.binding,
            store=DurableObjectStore(harness.disposable.store_root),
            ledger=RunEffectLedger("run-crash"),
        )
        with self.assertRaises(AmbiguousEffectRefused) as refused:
            recovered.execute(
                specification=harness.specification,
                proposal=harness.proposal,
                decision=harness.decision,
                reservation_id="reservation-1",
                receipt_id="receipt-1",
            )
        self.assertEqual(
            refused.exception.report.classification, "STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION"
        )
        self.assertFalse(refused.exception.report.replay_permitted)
        self.assertEqual(recovered.effect_invocation_count, 0)
        self.assertEqual((harness.disposable.workspace / TARGET_FILE).read_bytes(), first_bytes)

    def test_a_completed_effect_is_never_executed_twice(self) -> None:
        with DisposableWorkspace() as disposable:
            specification = build_specification("DIRECT", run_id="run-once")
            binding = WorkspaceBinding.bind(disposable.workspace, specification)
            self.addCleanup(binding.close)
            store = DurableObjectStore(disposable.store_root)
            substrate = SharedEffectSubstrate(
                binding=binding, store=store, ledger=RunEffectLedger("run-once")
            )
            request = WriteFileRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                path=TARGET_FILE,
                content=TARGET_CONTENT,
            )
            proposal = build_proposal(specification, request, proposal_id=PROPOSAL_ID)
            decision = decision_for(proposal)
            first = substrate.execute(
                specification=specification,
                proposal=proposal,
                decision=decision,
                reservation_id="reservation-1",
                receipt_id="receipt-1",
            )
            self.assertEqual(first.receipt.status, "COMPLETED")
            with self.assertRaises(AmbiguousEffectRefused) as refused:
                substrate.execute(
                    specification=specification,
                    proposal=proposal,
                    decision=decision,
                    reservation_id="reservation-1",
                    receipt_id="receipt-1",
                )
            self.assertEqual(refused.exception.report.classification, "RECONCILED_COMPLETE")
            self.assertEqual(substrate.effect_invocation_count, 1)

    def test_a_read_only_ambiguity_is_classified_separately(self) -> None:
        from admissible.paired_runner.tool_schemas import ListFilesRequest

        with DisposableWorkspace() as disposable:
            specification = build_specification("DIRECT", run_id="run-readonly")
            binding = WorkspaceBinding.bind(disposable.workspace, specification)
            self.addCleanup(binding.close)
            injector = FaultInjector({FAULT_AFTER_STARTED_BEFORE_EFFECT})
            store = DurableObjectStore(disposable.store_root, injector=injector)
            substrate = SharedEffectSubstrate(
                binding=binding, store=store, ledger=RunEffectLedger("run-readonly"), injector=injector
            )
            request = ListFilesRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint, path="."
            )
            proposal = build_proposal(specification, request, proposal_id=PROPOSAL_ID)
            with self.assertRaises(InjectedFault):
                substrate.execute(
                    specification=specification,
                    proposal=proposal,
                    decision=decision_for(proposal),
                    reservation_id="reservation-1",
                    receipt_id="receipt-1",
                )
            report = reconcile_effect(store, run_id="run-readonly", proposal_id=PROPOSAL_ID)
            self.assertEqual(report.classification, "STARTED_AMBIGUOUS_READ_ONLY")
            self.assertFalse(report.replay_permitted)


CORRUPTION_TARGETS: tuple[tuple[str, str, object], ...] = (
    (OBJECT_KIND_PROPOSAL, "turn_id", CanonicalProposal.from_dict),
    ("decision", "decision", ModeDecision.from_dict),
    (OBJECT_KIND_RESERVATION, "reservation_id", EffectReservation.from_dict),
    (OBJECT_KIND_LIFECYCLE_STARTED, "run_id", observation_from_dict),
    ("lifecycle-terminal", "receipt_status", observation_from_dict),
    (OBJECT_KIND_RECEIPT, "outcome_reason", EffectReceipt.from_dict),
    ("filesystem-before", "entry_count", observation_from_dict),
    ("filesystem-after", "entry_count", observation_from_dict),
    ("git-before", "phase", observation_from_dict),
    ("git-after", "phase", observation_from_dict),
    (LEDGER_OBJECT_KIND, "run_id", EffectLedgerEntry.from_dict),
    ("reconciliation", "reconciliation_note", observation_from_dict),
)


class CorruptionFixtureTests(unittest.TestCase):
    """Every persisted object class fails closed when it is altered."""

    def _completed_store(self, disposable: DisposableWorkspace) -> DurableObjectStore:
        specification = build_specification("GOVERNED", run_id="run-corrupt")
        binding = WorkspaceBinding.bind(disposable.workspace, specification)
        self.addCleanup(binding.close)
        store = DurableObjectStore(disposable.store_root)
        substrate = SharedEffectSubstrate(
            binding=binding, store=store, ledger=RunEffectLedger("run-corrupt")
        )
        request = WriteFileRequest.create(
            tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
            path=TARGET_FILE,
            content=TARGET_CONTENT,
        )
        proposal = build_proposal(specification, request, proposal_id=PROPOSAL_ID)
        substrate.execute(
            specification=specification,
            proposal=proposal,
            decision=decision_for(proposal),
            reservation_id="reservation-1",
            receipt_id="receipt-1",
        )
        return store

    def test_every_persisted_class_is_corrupted_by_byte_and_by_field(self) -> None:
        self.assertEqual(len(CORRUPTION_TARGETS), 12)
        for object_kind, field, decoder in CORRUPTION_TARGETS:
            for mode in ("byte", "field"):
                with self.subTest(object_kind=object_kind, mode=mode):
                    with DisposableWorkspace() as disposable:
                        store = self._completed_store(disposable)
                        path = store.path_of(object_kind, PROPOSAL_ID)
                        original = path.read_bytes()
                        self.assertTrue(original)
                        if mode == "byte":
                            index = len(original) // 2
                            corrupted = bytearray(original)
                            corrupted[index] = corrupted[index] ^ 0x01
                            path.write_bytes(bytes(corrupted))
                            state = store.inspect(object_kind, PROPOSAL_ID).state
                            self.assertIn(state, {"CORRUPT", "PUBLISHED"})
                            if state == "PUBLISHED":
                                # Still canonical JSON, so the typed decoder is
                                # the layer that must fail closed.
                                with self.assertRaises((ValueError, Exception)):
                                    decoder(store.load(object_kind, PROPOSAL_ID))
                            else:
                                with self.assertRaises(Exception):
                                    store.load(object_kind, PROPOSAL_ID)
                        else:
                            payload = json.loads(original.decode("utf-8"))
                            payload[field] = _mutate(payload[field])
                            path.write_bytes(canonical_bytes(payload))
                            self.assertEqual(store.inspect(object_kind, PROPOSAL_ID).state, "PUBLISHED")
                            with self.assertRaises(Exception):
                                decoder(store.load(object_kind, PROPOSAL_ID))

    def test_a_corrupt_proposal_makes_reconciliation_fail_closed(self) -> None:
        with DisposableWorkspace() as disposable:
            store = self._completed_store(disposable)
            path = store.path_of(OBJECT_KIND_PROPOSAL, PROPOSAL_ID)
            path.write_bytes(b"{\"not\": \"canonical\"")
            report = reconcile_effect(store, run_id="run-corrupt", proposal_id=PROPOSAL_ID)
            self.assertEqual(report.classification, "FAILED_CLOSED_CORRUPT_DURABLE_OBJECT")
            self.assertIn(OBJECT_KIND_PROPOSAL, report.corrupt_objects)
            self.assertFalse(report.replay_permitted)

    def test_ledger_verification_reads_only_durable_bytes(self) -> None:
        with DisposableWorkspace() as disposable:
            store = self._completed_store(disposable)
            ledger = RunEffectLedger.verify(store, "run-corrupt", (PROPOSAL_ID,))
            self.assertEqual(len(ledger.entries), 1)
            self.assertEqual(ledger.entries[0].final_reconciliation_state, "RECONCILED_COMPLETE")
            self.assertTrue(ledger.proposal_ledger_fingerprint().value)
            self.assertTrue(ledger.effect_receipt_ledger_fingerprint().value)
            path = store.path_of(LEDGER_OBJECT_KIND, PROPOSAL_ID)
            payload = json.loads(path.read_bytes().decode("utf-8"))
            payload["condition_id"] = "DIRECT"
            path.write_bytes(canonical_bytes(payload))
            with self.assertRaises(Exception):
                RunEffectLedger.verify(store, "run-corrupt", (PROPOSAL_ID,))


def _mutate(value: object) -> object:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "-corrupted"
    if value is None:
        return "corrupted"
    if isinstance(value, list):
        return value + ["corrupted"]
    raise TypeError(f"no mutation defined for {type(value).__name__}")


if __name__ == "__main__":
    unittest.main()
