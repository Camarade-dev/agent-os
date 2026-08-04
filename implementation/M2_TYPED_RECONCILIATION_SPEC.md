# M2 Typed Reconciliation Specification

The one authoritative reconciliation path, derived from durable bytes.

Implemented by `admissible/paired_runner/reconciliation.py`, with the durable
run index in `admissible/paired_runner/run_index.py`.

---

## 1. The defect this replaces

Milestone 2 reconciled by asking the object store which *names* existed. That is
a presence check, not a reconciliation. Three consequences followed:

1. An object could be replaced with a canonical record of the wrong type, from a
   different run, for a different proposal, or from an earlier attempt, and the
   classification still read `RECONCILED_COMPLETE`.
2. `RunEffectLedger.verify` re-read only the ledger entry's own bytes. It
   succeeded even when **every object the entry referenced had been deleted**.
3. Worst of all, the ledger entry *declared* `RECONCILED_COMPLETE` before
   reconciliation had been attempted. The record reconciliation was supposed to
   check was also the record asserting the answer.

> Canonical JSON is not evidence. A record is trustworthy only when it
> reconstructs as its exact declared type *and* agrees with every other record
> in its chain.

## 2. The non-circular design

The circularity is removed by splitting the claim from the verdict.

| Record | Role | May it claim success? |
| --- | --- | --- |
| `EffectLedgerEntry` | immutable **pending** claim of what happened | **No** |
| `FinalReconciliation` | separate verdict, written only after verification | Yes |

`EffectLedgerEntry.final_reconciliation_state` is constrained at the type level:

```python
_require_member(self.final_reconciliation_state, ("PENDING_VERIFICATION",), ...)
```

A ledger entry that predeclares its own successful reconciliation **cannot be
constructed at all**, in memory or on disk.

`FinalReconciliation` binds:

- the exact `pending_ledger_entry_fingerprint` it verified;
- the exact `experiment_specification_fingerprint`;
- `verified_object_kinds` and a `verified_object_set_fingerprint` over the
  `(kind, id, record fingerprint, content fingerprint)` of every object loaded;
- `verified` / `verdict` / `refusal_code`.

Validation forbids the two incoherent shapes: a verified record carrying a
refusal code, and an unverified record naming no refusal.

## 3. Inputs

Reconciliation requires the exact experiment specification **or** an externally
supplied exact specification fingerprint. Nothing weaker is accepted; with
neither, `TypedChainVerifier` refuses with `SPECIFICATION_UNAVAILABLE`. The
specification is an *external* input precisely so the chain cannot certify
itself.

## 4. Objects loaded and validated

Each object is loaded from durable bytes and reconstructed as its exact typed
class. Loading a canonical record of any other type into a slot is a
substitution and fails.

| Object kind | Typed class |
| --- | --- |
| `proposal` | `CanonicalProposal` |
| `decision` | `ModeDecision` |
| `reservation` | `EffectReservation` |
| `lifecycle-started`, `lifecycle-terminal` | `LifecycleRecord` |
| `filesystem-before`, `filesystem-after` | `FilesystemObservation` |
| `git-before`, `git-after` | `GitObservation` |
| `process-observation` | `ProcessObservation` |
| `stdout-observation`, `stderr-observation` | `StreamObservation` |
| `resource-observation` | `ResourceObservation` |
| `effect-receipt` | `EffectReceipt` |
| `reconciliation` | `EffectReconciliationReport` |
| `effect-ledger-entry` | `EffectLedgerEntry` |

The typed request and result are validated transitively: the proposal carries
the exact `ToolRequest` and the receipt carries the exact `ToolResult`, and both
are reconstructed as part of their parent records.

## 5. Cross-checks

Beyond typing, the verifier enforces the bindings between objects:

- **Wrong proposal** — the proposal's `proposal_id` must be the one requested.
- **Wrong run** — proposal, both lifecycle records, and the reconciliation
  report must all name the requested `run_id`.
- **Wrong specification** — the proposal's specification fingerprint must equal
  the supplied one; when the specification object is available,
  `validate_for_specification` must also pass.
- **Decision binding** — `decision.validate_for_proposal(proposal)`.
- **Reservation binding** — `validate_for_decision`, plus the reservation's
  proposal fingerprint.
- **Stale record** — each lifecycle record's proposal and reservation
  fingerprints must match the *current* proposal and reservation, so a record
  left by an earlier attempt is caught.
- **Wrong domain / phase substitution** — a `BEFORE_EFFECT` observation in an
  `AFTER_EFFECT` slot is refused; the stdout slot must hold `stream_name ==
  "stdout"` and stderr likewise.
- **Wrong order** — a terminal lifecycle record whose `monotonic_ns` precedes
  its own `STARTED` record is refused.
- **Lifecycle vs receipt** — `terminal.receipt_status` must equal
  `receipt.status`.
- **Receipt closure** — `receipt.validate_for_causal_chain(...)`.

### 5.1 Every ledger field is compared to the reconstructed object

`_check_ledger_entry` compares, field by field: `run_id`, `proposal_id`,
`condition_id`, `session_id`, `proposal_fingerprint`, `decision_fingerprint`,
`decision_value`, `tool_name`, `effect_classification`,
`tool_request_fingerprint`, `effect_receipt_fingerprint`,
`experiment_specification_fingerprint`, `reservation_id`,
`reservation_fingerprint`, `tool_result_fingerprint`,
`lifecycle_receipt_fingerprints`, and all eight observation fingerprints
(`filesystem_*`, `git_*`, `process_*`, `stdout_*`, `stderr_*`, `resource_*`).

A mismatch on any one of them is `LEDGER_FIELD_CONTRADICTS_OBJECT`.

## 6. The exact expected object set

`expected_object_kinds` derives the required set from the decision, the tool,
the effect classification, and whether a terminal lifecycle record exists. Both
directions are enforced: a missing object is `EXPECTED_OBJECT_ABSENT` and a
surplus object is `UNEXPECTED_OBJECT_PRESENT`.

| Situation | Expected set |
| --- | --- |
| decision refuses | proposal, decision, receipt, reconciliation |
| permitted, physically refused before `STARTED` | + reservation |
| permitted and started | + lifecycle-started, filesystem-before/after, git-before/after |
| tool is `run_command` (`PROCESS_EXECUTION`) | + process, stdout, stderr, resource observations |
| terminal lifecycle present | + lifecycle-terminal, ledger entry |

A `run_command` chain carrying no process observation and a read-only chain
carrying one are equally wrong.

## 7. Failure classes — all fail closed

| Refusal code | Cause |
| --- | --- |
| `SPECIFICATION_UNAVAILABLE` | neither specification nor exact fingerprint supplied |
| `OBJECT_ABSENT` | a referenced object was deleted |
| `OBJECT_CORRUPT` | committed bytes are not canonical |
| `OBJECT_NOT_THE_EXPECTED_TYPE` | substitution — canonical, but the wrong record |
| `WRONG_RUN` / `WRONG_PROPOSAL` / `WRONG_SPECIFICATION` | foreign record |
| `STALE_RECORD` | a record from an earlier attempt |
| `LIFECYCLE_SUBSTITUTED` / `OBSERVATION_PHASE_SUBSTITUTED` / `STREAM_SUBSTITUTED` | wrong domain in a slot |
| `WRONG_ORDER` | causal order violated |
| `LEDGER_FIELD_CONTRADICTS_OBJECT` | a ledger field disagrees with its object |
| `LEDGER_PREDECLARES_RECONCILIATION` | a ledger entry claims a verdict |
| `EXPECTED_OBJECT_ABSENT` / `UNEXPECTED_OBJECT_PRESENT` | object set is not exact |
| `RECEIPT_DOES_NOT_CLOSE_THE_CHAIN`, `DECISION_DOES_NOT_BIND_PROPOSAL`, `RESERVATION_DOES_NOT_BIND_DECISION` | causal binding broken |

## 8. `RunEffectLedger.verify`

`verify` now admits an entry only after `reconcile_typed_chain` verifies the
**whole chain behind it**. Re-reading an entry's own bytes proves the entry is
well formed and nothing more, which is why the previous implementation
succeeded with every referenced object deleted.

## 9. Publication receipts

Publication receipt fingerprints remain part of the ledger entry
(`publication_receipt_fingerprints`), and the receipts they name are the typed
`PublicationReceipt` records returned by each `DurableObjectStore.publish`.
These are retained as an accounting of the publication sequence; they are not
treated as independently verifiable durable objects, and no reconciliation
verdict depends on them. The authoritative set is
`verified_object_set_fingerprint`, which covers only objects that were actually
loaded, typed, and cross-checked.

## 10. The durable run index

`run_index.py` closes M2-R10. Each `RunIndexEntry` is an immutable link in a
hash chain carrying its own `sequence` and the `previous_entry_fingerprint`.

- **Every proposal is indexed, including refusals.** `DECISION_REFUSED` and
  `EFFECT_REFUSED` are first-class outcomes; a run that refused a proposal
  attempted that proposal, and the durable record says so.
- **Causal order is durable.** Sequence and predecessor fingerprint are part of
  the record, not of a caller-supplied in-memory list.
- **Reconstructible from bytes.** `load_all()` walks `run-index-<run>-<seq>`
  objects and re-verifies the chain.
- **Detects omission, duplication, reordering, cross-run substitution.** A gap
  truncates the chain; a repeated proposal, a broken predecessor link, a
  sequence that disagrees with its position, or a foreign `run_id` all raise
  `RunIndexBroken`.
- **Safe restart.** `head_sequence()` reads durable bytes, so a restarted
  process cannot silently begin as though the run were new.
- **Provider-free and single-session.** No model, transport, token, cost, or
  continuation field exists. This closes only the durable evidence substrate a
  later milestone would need; no model continuation is implemented.

## 11. Physical refusal lifecycle (M2-R06)

Preparation (`prepare_effect`) resolves every physical precondition and
*retains the descriptors it proved* **before** any `STARTED` record is
published. A refusal is therefore genuinely pre-effect, and the receipt
(`REFUSED`, `effect_started=false`), the absent `STARTED` record, the absent
ledger entry, the run index (`effect_crossed_boundary=false`), and the typed
reconciliation all agree.

Because the descriptors are retained, execution acts on the very objects that
were checked — not on a path string that could have been swapped in between.
Directory creation for `create_parents` is deliberately excluded from
preparation, because creating a directory is itself a mutation and must happen
after `STARTED`.


## Addendum — Milestone 2 second critical repairs

### Reconciliation is no longer the last word on the run

A verified `FinalReconciliation` proves that one proposal's typed chain
reconstructs and agrees with itself. It says nothing about whether the *run*
records that proposal. Those are now separate obligations:

* the durable event chain records every transition, and the `PROPOSAL_PUBLISHED`
  event is durable before any effect is possible;
* the closing `RECONCILIATION_PUBLISHED` event binds the verified final
  reconciliation's fingerprint, the terminal receipt's, and the ledger entry's.

A crash between a durable verified reconciliation and its closing event is
therefore recoverable: `effects.recover_run_index` reads the durable objects and
appends only the missing events. It writes no proposal, reservation, lifecycle
record, receipt, or reconciliation, so it cannot cause an effect. An *unverified*
final reconciliation closes nothing — the proposal stays open.

### The ledger is derived from the index

`RunEffectLedger.verify` no longer accepts the proposal identities to check. It
derives them from the durable index, which is itself chain-verified against its
committed head first. For every indexed proposal the whole typed chain is
reconciled through `reconcile_typed_chain` exactly as before; what changed is
that no caller can decide which proposals that applies to.

See `implementation/M2_DURABLE_EVENT_INDEX_SPEC.md` §4.

### §7 is superseded

The Git observation section of this specification described running `git` inside
the capsule behind command-line overrides. That construction is withdrawn: it
executed repository-selected filter drivers. The observer now executes nothing.
See ADR-M2S-02 and `implementation/M2_SECOND_CRITICAL_REPAIR_REPORT.json`.
