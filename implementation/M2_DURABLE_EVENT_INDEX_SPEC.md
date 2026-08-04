# M2 Durable Event Index Specification

Branch: `paired-runner/m2-causal-index-and-ipc-repairs`
Starting commit: `6383f765520e3d98c7359118704d063b6aa39b52`
Closes: **M2-B14**, **M2-B15**, **M2-B16**

## 1. What was wrong

The Milestone 2 index stored **one final summary object per proposal** and
discovered its own extent by counting upward from sequence zero until a name was
absent. Three defects followed, and the independent audit demonstrated all
three.

**Truncation was invisible (M2-B14).** `load_all()` stopped at the first absent
object and never looked past it. Deleting entry 1 of `[0, 1, 2]` returned `[0]`
— a shorter chain that verified perfectly, while entry 2 still sat on disk. The
shipped test `test_an_omitted_entry_is_detected` asserted the truncated length of
1 as the expected result, so the suite validated the defect. Reproduced before
repair:

```
before deletion: [0, 1, 2]
delete entry 1
entry 2 still exists: PUBLISHED
load_all result: [0]
no RunIndexBroken raised
```

Deleting the *newest* entry was worse: nothing durable stated how far the run had
got, so a truncated run and a run that had always been that short were
byte-identical. `RUN_INDEX_HEAD_KIND` was declared and never used.

**A completed effect could be unindexed (M2-B15).** The single summary was
appended last, after the typed reconciliation. A process that died in that window
left a real effect, a verified final reconciliation, a durable ledger entry — and
no index entry at all. Replay was correctly refused on restart, but the run's
authoritative order silently omitted a completed effect. A one-entry-per-proposal
model cannot represent a crash *between* the proposal and its outcome, so this
was a design limit, not a missing line of code.

**History was a caller parameter (M2-B16).** `RunEffectLedger.verify` took the
proposal identities to verify. A restarted process could hand in an empty tuple
and receive a ledger that verified perfectly while omitting every effect the run
had already performed.

## 2. The construction

### 2.1 Immutable events

`run-index-event` objects are hash-chained links, one per **transition**, not one
per proposal. Each carries its own `sequence`, the `previous_event_fingerprint`
of the event before it, and the exact transition it records. Object identity is
`run-index-event.<run_id>-<sequence:08d>.json`, so the sequence is part of the
immutable identity and a gap is a missing *name*.

| Event kind | Published when | Terminal |
| --- | --- | --- |
| `PROPOSAL_PUBLISHED` | the canonical proposal is durable | no |
| `DECISION_PUBLISHED` | a permitting decision is durable | no |
| `RESERVATION_PUBLISHED` | the reservation is durable | no |
| `EFFECT_STARTED` | the `STARTED` lifecycle record is durable | no |
| `TERMINAL_RECEIPT_PUBLISHED` | the terminal receipt is durable | no |
| `RECONCILIATION_PUBLISHED` | the verified final reconciliation is durable | **yes** |
| `DECISION_REFUSED` | the decision refused the proposal | **yes** |
| `EFFECT_REFUSED_BEFORE_START` | physical preconditions refused pre-`STARTED` | **yes** |
| `EFFECT_AMBIGUOUS` | replay refused over ambiguous durable state | **yes** |

`EFFECT_STARTED` binds the `capsule_runtime_manifest_fingerprint`, so each effect
names the exact capsule that carried it. Terminal events carry the `outcome` and,
for effect-bearing proposals, the `effect_receipt_fingerprint`, the
`ledger_entry_fingerprint`, and the `final_reconciliation_fingerprint`.

**The proposal event is durable before any effect is possible.** `execute()`
publishes the proposal object and immediately appends `PROPOSAL_PUBLISHED`, both
before the decision is validated and long before the effect boundary. No effect
can exist outside the run's causal order.

### 2.2 The committed head

`run-index-anchor.<run_id>.json` records `run_id`, `head_sequence`,
`event_count`, and `head_event_fingerprint`. It is the **one replaceable object**
in an otherwise no-replace store, published through
`DurableObjectStore.publish_anchor` with temp write → `fsync` → atomic `rename` →
directory `fsync`, so a reader sees the previous head or the new one and never a
partial document.

A committed head cannot be immutable. Without a single name that always states
how far a run got, deleting the newest event together with its head record leaves
a shorter chain that is internally consistent and therefore undetectable. Exactly
one object is allowed to move, it moves only forward, and it moves only after the
event it commits is already durable.

### 2.3 Reconstruction

`durable_sequences()` scans **every** committed name belonging to the run.
Counting until absence is gone. `state()` then classifies:

| State | Condition |
| --- | --- |
| `EMPTY` | no events and no anchor |
| `COMMITTED` | positions are exactly `0..n-1`, the chain verifies, and the head names the newest event |
| `HEAD_UPDATE_PENDING` | as above, but the head names the newest event's predecessor |

Everything else raises `RunIndexBroken`:

* a gap or a surplus position (the set of positions is not `0..n-1`);
* a corrupt or non-reconstructible event;
* an event whose declared sequence differs from its position;
* an event that does not follow its predecessor's fingerprint (reordering, mid-chain substitution);
* an event belonging to another run;
* a proposal proposed twice, an event for a proposal never indexed as proposed, or an event after that proposal was closed;
* an anchor from another run, an anchor whose fingerprint does not match the event it names, an anchor that outruns the chain, an anchor lagging by more than one event, or a missing anchor over a non-empty chain.

An absent anchor is treated as head sequence `-1` — the committed head of a run
that has committed nothing — so a crash before the very first head update is a
position in the same classification, not a special case.

### 2.4 Recovery

`DurableRunIndex.recover_head()` advances the anchor onto an event that is
**already durable and already chained**. It writes no event and re-executes
nothing.

`effects.recover_run_index(store, run_id)` closes index events whose durable
objects already exist. For each open proposal it reads the durable objects,
determines which transitions were never indexed, and appends exactly those. It
writes no proposal, no reservation, no lifecycle record, no receipt, and no
reconciliation; every event it appends describes an object that was on disk
before it was called. `RunIndexRecovery.replayed_any_effect` is structurally
`False`.

This is the closure of M2-B15: a crash after a verified final reconciliation but
before the closing index event leaves every earlier transition indexed, and
recovery appends the one missing `RECONCILIATION_PUBLISHED` event derived from
the durable `FinalReconciliation`, the durable receipt, and the durable ledger
entry. An unverified final reconciliation closes nothing — the proposal stays
open and a human decides.

`append_event` refuses outright while the head is pending: a pending head is a
recoverable crash state, never a base to build on.

## 3. Crash points

Six fault points cover every boundary of the event and head publication, and each
has a literally declared row in `implementation/M2_CRASH_MATRIX.json` and in
`tests/test_admissible_paired_runner_m2_crash.py`:

| Fault point | Durable state | Index state |
| --- | --- | --- |
| `BEFORE_INDEX_EVENT_PUBLICATION` | proposal only | `EMPTY` |
| `RUN_INDEX_EVENT_PUBLICATION:TEMP_WRITE` | proposal only, partial publication present | `EMPTY` |
| `AFTER_INDEX_EVENT_BEFORE_ANCHOR_UPDATE` | proposal, event 0 durable | `HEAD_UPDATE_PENDING` |
| `RUN_INDEX_ANCHOR_UPDATE:TEMP_WRITE` | as above, partial publication present | `HEAD_UPDATE_PENDING` |
| `RUN_INDEX_ANCHOR_UPDATE:AFTER_FILE_FSYNC_BEFORE_COMMIT` | as above | `HEAD_UPDATE_PENDING` |
| `RUN_INDEX_ANCHOR_UPDATE:AFTER_COMMIT_BEFORE_DIRECTORY_FSYNC` | head renamed into place | `COMMITTED` |

Every `HEAD_UPDATE_PENDING` row is then recovered in the same test, and the effect
invocation count and workspace bytes are re-asserted afterwards to prove nothing
was replayed.

## 4. The effect ledger is derived, not supplied (M2-B16)

`RunEffectLedger.verify(store, run_id, *, specification=..., index=...,
require_closed=True)` has **no** `proposal_ids` parameter. The ordered proposal
set comes from `DurableRunIndex.indexed_proposal_ids()`, and the index is itself
chain-verified against its committed head first, so no caller can choose what is
checked. For every indexed proposal:

* the whole typed chain is reconciled through `reconcile_typed_chain`;
* an effect-bearing proposal must have a ledger entry whose `record_fingerprint`
  and `effect_receipt_fingerprint` the index already recorded;
* a refused proposal must have **no** ledger entry, and that absence is checked
  rather than assumed;
* a ledger entry in the store that the index never recorded is surplus and fails
  closed.

`require_closed` is the only dial and it does not select history: it decides what
happens to a proposal a crash left open. With `require_closed=False` such a
proposal is excluded and named in `open_proposal_ids` instead of failing the
derivation, which is what lets a restarted controller look at the run in order to
*refuse* replaying it. Every closed proposal is verified equally strictly either
way.

`SharedEffectSubstrate.preflight` rebuilds the in-memory ledger from this derived
history before any new proposal is published, and `RunEffectLedger.adopt` allows
only *extension*: whatever the ledger already recorded must still be present, in
the same order, at the same positions, with the same entry fingerprints. An empty
in-memory ledger over a non-empty durable run is refilled; a non-empty one that
contradicts the durable history is `LEDGER_CONTRADICTS_DURABLE_HISTORY`.

`proposal_ledger_fingerprint` and `effect_receipt_ledger_fingerprint` accept the
durable index head and include it, together with the entry count, in the
fingerprinted payload — binding those fingerprints to the complete history rather
than to whatever subset is in memory.

## 5. Stated residual weakness: rollback

Deleting the newest event **and** rewinding the committed head to a still-valid
earlier head produces a shorter run that is entirely self-consistent. No purely
local record can detect it. Detecting it requires an anti-rollback anchor held
outside this store — a witness, a monotonic counter, or an external attestation —
which Milestone 2 deliberately does not implement.

`DurableRunIndex.head_anchor()` returns exactly the value such an external anchor
would pin: `{run_id, head_sequence, head_event_fingerprint}`. This is stated as a
requirement on any future multi-session design, not as a closed defect.
