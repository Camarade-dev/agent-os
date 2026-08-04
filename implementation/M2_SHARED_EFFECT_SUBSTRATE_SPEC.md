# Admissible Paired Runner — Milestone 2
## Shared Observation and Effect Substrate

Status: `SHARED_EFFECT_SUBSTRATE_VERIFIED` at the provider-free substrate
boundary, with the explicit limitations recorded in section 10.

This milestone starts at the independently accepted Milestone 1 commit
`5b5c3874f1929e77dbc3e2f71aa7f26d675a2705` on branch
`paired-runner/m2-shared-effect-substrate`. The frozen governing inputs remain
the plan digest
`0a4316efa770550e50b9218e15782e95a1f96c7440a1a9062a3bd80f6cbfbe24` and the audit
digest `4802411063a144b6983d64cc2e7ffab0a64665f4fcd9a88cf2c04c3d8809c4ab`.

Milestone 3 has not begun. No model transport, Codex app-server communication,
Cursor path, multi-session continuation, direct-mode orchestrator, governed-mode
orchestrator, policy engine, owner authorization, broker, provider contact,
evaluator engine, benchmark task, paired environment preparation, production
installation, mint, witness, or V14–V18 action exists in this milestone.

---

## 1. Scope

Milestone 2 builds **one** provider-free, model-free physical substrate that
both future conditions will use. It closes only these fifteen requirements:
EXEC-02, EXEC-05, EXEC-06, EVID-01 through EVID-08, LONG-07, LONG-08, TEST-03,
and TEST-08. Every other requirement record is untouched.

The platform decision is separate and mandatory reading:
`M2_PLATFORM_AND_DURABILITY_CONTRACT.md` (ADR-015).

## 2. Module surface

| Module | Responsibility | Boundary preserved |
|---|---|---|
| `admissible/paired_runner/observation.py` | Typed, versioned M2 observation records with explicit metric availability | No I/O, no policy, no acceptance |
| `admissible/paired_runner/durable_store.py` | The single canonical durable publication primitive and the fault-injection points | No object semantics, no ledger logic |
| `admissible/paired_runner/process_supervision.py` | Bounded local process supervision, timeout, cancellation, group termination, stream accounting | No workspace policy, no receipts |
| `admissible/paired_runner/effects.py` | Workspace binding, the four tool implementations, the shared executor, crash-safe reconciliation | No mode-specific path, no policy engine |
| `admissible/paired_runner/effect_ledger.py` | The provider-free run/effect ledger and its durable verification | No terminal acceptance |

No `transport.py`, `direct_mode.py`, `governed_mode.py`, `policy.py`,
`authority.py`, `evaluator.py`, `archive.py`, provider adapter, model adapter,
or multi-session orchestrator was created. No unused abstraction was introduced:
every type in these modules is constructed and asserted by the test suite.

## 3. The shared-substrate invariant

There is exactly one physical execution object, `SharedEffectSubstrate`, with
exactly one entry point:

```text
SharedEffectSubstrate.execute(
    specification: ExperimentSpecification,
    proposal:      CanonicalProposal,
    decision:      ModeDecision,
    reservation_id, receipt_id,
) -> EffectExecutionOutcome
```

It receives typed Milestone 1 objects, never a mode-specific command path, and
it reconciles `ExperimentSpecification`, `CanonicalProposal`, `ModeDecision`,
and `EffectReservation` before any effect.

```text
proposal (durably published)
   -> decision
        |-- DIRECT   : DIRECT_EXECUTION  --.
        |-- GOVERNED : ALLOW             --+--> _execute_permitted_effect  (one implementation)
        `-- GOVERNED : REFUSE / TERMINATE_RUN / REQUIRE_CONTINUATION
                        -> REFUSED receipt, no reservation, no effect
```

`decision.permits_effect` is the only place the decision is consulted. After
that point nothing inspects the condition, the decision value, or any governance
field. `_execute_permitted_effect`, `_cross_effect_boundary`, and the four tool
functions are one implementation, not two that agree.

This is proved two ways in
`tests/test_admissible_paired_runner_m2.py::SharedExecutorIdentityTests`:

* a `sys.settrace` capture of every `(function, line)` executed inside
  `effects.py` after the decision boundary is **set-equal** for a DIRECT
  `DIRECT_EXECUTION` fixture and a GOVERNED `ALLOW` fixture — the executed
  branches are identical, not merely equivalent;
* the resulting typed results, request fingerprints, and effect classifications
  are equal, while only the decision value differs.

**Milestone 2 contains no policy engine.** `ModeDecision` is an input the
substrate obeys and reconciles; nothing here decides whether a proposal *should*
be allowed. No test claims otherwise.

## 4. Physical workspace binding

`WorkspaceBinding.bind(root, specification)` binds:

* an absolute physical root;
* the canonical resolved root (which must equal the physical root);
* the exact M1 `working_root_identity`;
* the exact M1 `scope_identity`;
* an initial filesystem observation fingerprint;
* the experiment specification fingerprint;
* whether Git is present, and the initial Git observation when it is.

`validate_for_specification` refuses a binding from another experiment. The root
itself must not be a symlink, and a relative root is refused.

Confinement is descriptor-relative and fail-closed: every component is opened
with `O_NOFOLLOW` from a directory descriptor anchored at the root, so there is
no "check the string, then open an arbitrary path" race. All tool paths stay
relative POSIX paths; absolute paths, `..`, backslash aliases, and NUL are
refused by the Milestone 1 request type before the substrate is reached.

Section 3 of the platform contract records the one unavoidable CPython
limitation (`Popen` takes a `cwd` string, not a descriptor).

## 5. Proposal-before-effect protocol

The substrate physically enforces this order and no other:

1. validate the experiment specification and the workspace binding;
2. validate the proposal for that exact specification;
3. durably publish the canonical proposal;
4. validate the decision for that exact proposal, and publish it;
5. refuse to replay if durable state already exists for this proposal;
6. construct and durably publish the exact reservation;
7. durably publish the pre-effect `STARTED` lifecycle record;
8. observe the filesystem and Git state;
9. **only then** cross the local effect boundary;
10. observe the result and publish the process/stream/resource observations;
11. construct and durably publish the terminal receipt and the `TERMINAL`
    lifecycle record;
12. publish the ledger entry and the reconciliation report;
13. re-verify the ledger from durable bytes.

The effect boundary is instrumented. `_cross_effect_boundary` calls an optional
hook immediately before dispatch, and
`ProposalBeforeEffectOrderTests` uses that hook to read the *filesystem* — not
memory — and assert that the proposal, the reservation, and the `STARTED` record
are all already committed and byte-verified at that instant, for both DIRECT and
GOVERNED. A refusing decision never reaches the hook, never increments
`effect_invocation_count`, and leaves no reservation and no `STARTED` record.

## 6. Durable publication

Described normatively in section 4 of the platform contract. The seven
publication states, the no-replace `link()` commit, the explicit idempotency
rule, the restrictive `0600` mode, the `O_NOFOLLOW` temporary creation, the
read-back verification, and the typed `PublicationReceipt` are all covered by
`DurablePublicationTests`.

## 7. Ledger design

`EffectLedgerEntry` binds, for exactly one effect: the specification
fingerprint, run/condition/session identity, the proposal fingerprint, the
decision fingerprint and value, the reservation identity and fingerprint, the
ordered lifecycle receipt fingerprints, the effect receipt fingerprint, the tool
name and effect classification, the tool request fingerprint, the typed result
fingerprint when one exists, every publication receipt fingerprint, wall-clock
and monotonic observations, the filesystem and Git observations before and
after, the process/stdout/stderr/resource observation fingerprints, whether the
effect crossed the boundary, and the final reconciliation state.

`RunEffectLedger.verify` rebuilds the ledger **from durable bytes only**: each
entry is re-read, re-parsed canonically, and re-validated as a typed record.
Nothing in memory is trusted.

### Terminal fingerprint domains

Milestone 2 does not implement evaluator acceptance and marks no model task
accepted. It does remove the ambiguity about which typed object stands behind
each future terminal fingerprint field:

| Terminal field | Fixed domain | Typed object |
|---|---|---|
| `proposal_ledger_fingerprint` | `admissible.paired_runner.m2.proposal_ledger.fingerprint` | ordered proposal identities/fingerprints of one `RunEffectLedger` |
| `effect_receipt_ledger_fingerprint` | `admissible.paired_runner.m2.effect_receipt_ledger.fingerprint` | ordered receipt and ledger-entry fingerprints of one `RunEffectLedger` |
| `budget_resource_observation_fingerprint` | `admissible.paired_runner.m2.resource_observation.fingerprint` | `ResourceObservation` |
| `repository_filesystem_observation_fingerprint` | `admissible.paired_runner.m2.filesystem_observation.fingerprint` | `FilesystemObservation` |

A terminal manifest may cite these only after the corresponding typed ledger
validates.

## 8. Crash semantics and reconciliation

Thirteen deterministic fault-injection points are declared in
`durable_store.py`; the injector is inert unless a test arms it, and
`InjectedFault` derives from `BaseException` so ordinary error handling cannot
convert a simulated crash into a normal outcome. A simulated crash deliberately
skips every cleanup step, so the durable state is frozen exactly as process
death would leave it.

Required semantics, all asserted in `M2_CRASH_MATRIX.json` and the crash tests:

* before durable `STARTED` publication: no effect can have occurred;
* after durable `STARTED` but before an observed terminal result: the effect
  state is ambiguous;
* after an effect may have occurred and before a terminal receipt is durable:
  **never auto-replay** — `replay_permitted` is false in every classification;
* a mutating ambiguous effect is classified
  `STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION`; a read-only one is
  classified separately as `STARTED_AMBIGUOUS_READ_ONLY`;
* duplicate effect execution is forbidden: a fresh controller restarted against
  the same durable store raises `AmbiguousEffectRefused` and never re-enters the
  boundary, and a completed effect is refused the same way;
* recovery reconstructs only from durable bytes;
* temporary partial files carry a reserved prefix, are reported explicitly, and
  are never counted as committed objects;
* a corrupted committed object fails closed
  (`FAILED_CLOSED_CORRUPT_DURABLE_OBJECT`).

Milestone 2 does not implement full multi-session restart. It implements
deterministic single-effect recovery and reconciliation for Milestone 3 to build
on.

## 9. Process supervision and bounded output

The audited defect (AUD-MJ06: an unbounded `_StreamPump.queue`) is not reused.
The new path has no queue at all. One `selectors` loop drains both pipes and
enforces both the timeout and cancellation, so neither can deadlock on a full
pipe. Per stream the controller keeps a retention buffer capped at
`max_output_bytes`, a full byte counter, and an incremental SHA-256 of the whole
stream.

Controller memory is bounded by `2 * max_output_bytes + 262144` bytes and is
independent of total output volume. Section 9 of the platform contract records
the 64 MiB measured-RSS threshold, which was declared before the heavy soak ran.

Descriptors are always closed, the child is always reaped, escalation is
ordered, and the process group is checked for emptiness. Resource observations
are best-effort with explicit availability. No token or model cost metric is
claimed.

## 10. Known limitations

1. Every measurement was taken under WSL2; this is not clean-host Linux
   qualification.
2. `fsync` is claimed only as "the flush was requested and the bytes read back";
   device-level and power-loss durability were not tested.
3. `subprocess` accepts a `cwd` string, so the final `execve` is not
   descriptor-anchored (platform contract, section 3).
4. `RUSAGE_CHILDREN` aggregates all reaped children, so child CPU and RSS are an
   upper bound recorded as `OBSERVED_BEST_EFFORT`.
5. A descendant that calls `setsid` leaves the reachable process group.
6. Long *duration* coverage is bounded by the Milestone 1 60 000 ms command
   timeout; long-running multi-session duration is Milestone 3, so TEST-08 is
   closed for massive output only.
7. No installed-path execution, no provider, no policy, no authority: nothing
   here supports `VERIFIED_INSTALLED_PATH` for any requirement.
8. TEST-03 is closed only at the provider-free shared-substrate boundary; it is
   not proof of complete future A/B runners.

---

## Milestone 2 critical repairs — substrate changes

The execution order gains three steps, and one step changes meaning. The
substrate still contains no policy engine, and the condition is still not an
input to any branch after the decision is reduced to "an effect is permitted".

### Revised order

0. **Preflight** (new). Every configuration and identity check runs *before*
   the proposal is durable: ledger run identity, run-index run identity,
   specification/proposal run agreement, workspace/specification binding,
   executor identity, evidence-root identity and inode, workspace root inode,
   tool catalogue membership, capsule readiness, and run-index integrity. No
   configuration error can be discovered after an effect.
1. Validate the specification and the workspace binding. **Binding executes
   nothing** — it is pure syscalls, so no process-capable observer runs before
   the proposal is durable.
2. Publish the canonical proposal.
3. Validate the decision; publish it. A refusal is indexed in the durable run
   index and returns.
4. Reconcile prior durable state; refuse rather than replay.
5. Publish the reservation.
5b. **Prepare** (new). Resolve every physical precondition and retain the
   proven descriptors. A refusal here is genuinely pre-effect: no `STARTED`
   record is published and nothing contradicts the receipt.
6. Publish `STARTED`; take the BEFORE observations.
7. Cross the effect boundary — inside the capsule.
8. Take the AFTER observations, **strictly after process-domain quiescence**.
   `supervise_command` returns only once the launcher has been reaped, and the
   launcher exits only after the in-capsule init observed `ECHILD`.
9. Publish the terminal receipt and terminal lifecycle record.
10. Publish the **pending** ledger entry (`PENDING_VERIFICATION`) and the
    reconciliation report.
11. Reconcile the complete typed chain and publish the **separate** final
    reconciliation record. A failed verification raises
    `TypedReconciliationRefused` rather than returning an outcome.
12. Verify the ledger by re-verifying every entry's whole typed chain, then
    append to the durable run index.

### New modules

| Module | Purpose |
| --- | --- |
| `sandbox.py` | the one capsule construction and its readiness probe |
| `_capsule_init.py` | the in-capsule PID 1 init that reaps and reports |
| `reconciliation.py` | the authoritative typed reconciliation path |
| `run_index.py` | the durable append-only run index |

### New refusal types

`SandboxUnavailable`, `EvidenceRootIsolationError`, `ConfigurationRefused`,
`TypedReconciliationRefused`, `ReconciliationRefused`, `RunIndexBroken`.


## Addendum — Milestone 2 second critical repairs

The single physical execution path is unchanged in shape: validate, publish the
proposal, validate the decision, reserve, publish `STARTED`, cross the boundary.
Four obligations were added to it, and one order changed.

**The order that changed.** Every transition is indexed as it happens, and the
proposal's index event is durable before the decision is even validated. The
previous design appended one summary per proposal after the typed reconciliation,
which meant a crash in that window left a real, completed, fully reconciled
effect that the run's causal order did not mention.

**Added obligations, all in `preflight`, all before anything is durable:**

1. the capsule's byte identity is re-derived and compared, including re-resolving
   the launcher through `PATH`;
2. a pending committed head is recovered before any new event is appended;
3. the in-memory effect ledger is rebuilt from the durable event index, and a
   ledger that contradicts that history is refused;
4. the specification's schema version is compared against the constant this
   substrate implements, first, before anything else is inspected on the strength
   of it.

**Added obligation at the effect boundary.** No capsuled process starts over a
workspace containing a socket, FIFO, or device node. The refusal is resolved in
`prepare_effect`, so it is genuinely pre-`STARTED`: the receipt is `REFUSED`, the
boundary is not crossed, and no lifecycle record exists.

The condition is still not an input to any function on this path. `_index`,
`prepare_effect`, the capsule, the seccomp program, and the resource bounds are
identical for a future DIRECT run and a future GOVERNED `ALLOW`.
