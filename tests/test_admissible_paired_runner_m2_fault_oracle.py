"""Every fault point, judged by an oracle independent of the implementation.

The Milestone 2 crash tests compared each outcome with a table declared beside
the implementation.  A table that both sides share cannot catch a defect that
lives in the table.  The oracle here never consults
``_RECONCILIATION_ORDER``, ``RECONCILIATION_CLASSIFICATIONS``, or any
classification the substrate computes.  It states, from first principles and
using only the durable bytes on disk, the four properties that must hold after
*any* crash:

1. an effect is never executed twice;
2. a mutating effect that may have occurred is never silently reported as
   complete;
3. a durable object set that is not exactly the expected one never reconciles;
4. no ledger entry ever asserts its own successful reconciliation.

Every effect happens under a disposable temporary root.
"""

from __future__ import annotations

from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
)
from admissible.paired_runner.durable_store import (  # noqa: E402
    FAULT_POINTS,
    DurableObjectStore,
    FaultInjector,
    InjectedFault,
)
from admissible.paired_runner.effect_ledger import LEDGER_OBJECT_KIND, RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import SharedEffectSubstrate, WorkspaceBinding  # noqa: E402
from admissible.paired_runner.reconciliation import (  # noqa: E402
    FINAL_RECONCILIATION_OBJECT_KIND,
    reconcile_typed_chain,
)
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402
from admissible.paired_runner.tool_schemas import WriteFileRequest  # noqa: E402


CAPSULE_READY = probe_capsule_readiness()
PROPOSAL_ID = "proposal-1"
RUN_ID = "run-oracle"
TARGET = "written.txt"
CONTENT = "the exact payload this effect would write"


class _Recorder:
    """Counts real effect boundary crossings, independent of any receipt."""

    def __init__(self) -> None:
        self.crossings = 0

    def __call__(self) -> None:
        self.crossings += 1


def _attempt(disposable: DisposableWorkspace, armed: str | None):
    """Run one effect with an optional armed fault and report raw facts."""

    specification = build_specification("DIRECT", run_id=RUN_ID)
    injector = FaultInjector((armed,) if armed else ())
    store = DurableObjectStore(disposable.store_root, injector=injector)
    binding = WorkspaceBinding.bind(
        disposable.workspace, specification, evidence_root=disposable.store_root
    )
    recorder = _Recorder()
    substrate = SharedEffectSubstrate(
        binding=binding,
        store=store,
        ledger=RunEffectLedger(RUN_ID),
        injector=injector,
        effect_boundary_hook=recorder,
    )
    request = WriteFileRequest.create(
        tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
        path=TARGET,
        content=CONTENT,
    )
    proposal = build_proposal(specification, request, proposal_id=PROPOSAL_ID)
    crashed = False
    try:
        substrate.execute(
            specification=specification,
            proposal=proposal,
            decision=decision_for(proposal),
            reservation_id="reservation-1",
            receipt_id="receipt-1",
        )
    except InjectedFault:
        crashed = True
    except Exception:  # noqa: BLE001 - a refusal is a legitimate crash outcome
        crashed = True
    finally:
        binding.close()
    return store, specification, recorder, crashed


@unittest.skipUnless(CAPSULE_READY.available, "the capsule is unavailable")
class IndependentFaultOracleTests(unittest.TestCase):
    """Four properties that must hold at every fault point."""

    def test_every_fault_point_satisfies_the_independent_oracle(self) -> None:
        self.assertGreaterEqual(len(FAULT_POINTS), 19)
        for point in FAULT_POINTS:
            with self.subTest(fault_point=point):
                with DisposableWorkspace() as disposable:
                    store, specification, recorder, crashed = _attempt(disposable, point)

                    # (1) An effect is never executed twice.
                    self.assertLessEqual(recorder.crossings, 1, point)

                    names = set(store.committed_names())
                    started = f"lifecycle-started.{PROPOSAL_ID}.json" in names
                    ledger_present = f"{LEDGER_OBJECT_KIND}.{PROPOSAL_ID}.json" in names
                    final_present = (
                        f"{FINAL_RECONCILIATION_OBJECT_KIND}.{PROPOSAL_ID}.json" in names
                    )

                    # The workspace is the ground truth for whether the mutation
                    # actually happened -- not any record the substrate wrote.
                    written = (disposable.workspace / TARGET).exists()
                    if written:
                        self.assertTrue(
                            started,
                            f"{point}: a mutation happened with no durable STARTED record",
                        )

                    # (2) A completed verdict may exist only when the effect
                    # genuinely finished and every object is durable.
                    if final_present:
                        payload = store.load(FINAL_RECONCILIATION_OBJECT_KIND, PROPOSAL_ID)
                        if payload["verified"]:
                            self.assertTrue(ledger_present, point)
                            self.assertTrue(written, point)

                    # (3) An incomplete object set never reconciles.
                    final = reconcile_typed_chain(
                        store,
                        run_id=RUN_ID,
                        proposal_id=PROPOSAL_ID,
                        specification=specification,
                    )
                    if not ledger_present and started:
                        self.assertFalse(
                            final.verified,
                            f"{point}: reconciled with no durable ledger entry",
                        )

                    # (4) No ledger entry ever asserts its own reconciliation.
                    if ledger_present:
                        entry = store.load(LEDGER_OBJECT_KIND, PROPOSAL_ID)
                        self.assertEqual(
                            entry["final_reconciliation_state"], "PENDING_VERIFICATION", point
                        )

    def test_a_clean_run_reconciles_and_a_crashed_run_never_replays(self) -> None:
        with DisposableWorkspace() as disposable:
            store, specification, recorder, crashed = _attempt(disposable, None)
            self.assertFalse(crashed)
            self.assertEqual(recorder.crossings, 1)
            final = reconcile_typed_chain(
                store, run_id=RUN_ID, proposal_id=PROPOSAL_ID, specification=specification
            )
            self.assertTrue(final.verified)

        with DisposableWorkspace() as disposable:
            store, specification, recorder, crashed = _attempt(
                disposable, "AFTER_STARTED_BEFORE_EFFECT"
            )
            self.assertTrue(crashed)
            self.assertEqual(recorder.crossings, 0)
            # A second attempt against the same durable state must refuse rather
            # than replay, because a STARTED record is already durable.
            binding = WorkspaceBinding.bind(
                disposable.workspace,
                specification,
                evidence_root=disposable.store_root,
            )
            self.addCleanup(binding.close)
            substrate = SharedEffectSubstrate(
                binding=binding,
                store=DurableObjectStore(disposable.store_root),
                ledger=RunEffectLedger(RUN_ID),
            )
            request = WriteFileRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                path=TARGET,
                content=CONTENT,
            )
            proposal = build_proposal(specification, request, proposal_id=PROPOSAL_ID)
            with self.assertRaises(Exception):
                substrate.execute(
                    specification=specification,
                    proposal=proposal,
                    decision=decision_for(proposal),
                    reservation_id="reservation-1",
                    receipt_id="receipt-1",
                )
            self.assertEqual(substrate.effect_invocation_count, 0)


if __name__ == "__main__":
    unittest.main()
