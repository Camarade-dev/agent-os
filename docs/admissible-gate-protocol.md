# Admissible delegated-gate protocol

## Purpose

This document is the canonical constitution for Admissible's delegated,
long-running work-gate mode. The mode is a package peer of
`admissible/v0_controller`; it does not extend the V0 write-operation reducer
and does not unify the earlier and later controller generations.

Act 1 supplies deterministic protocol machinery only: immutable contracts,
typed material checkpoints, typed independent-audit verdicts, a pure reducer,
atomic restartable persistence, and deterministic test fixtures. It does **not**
yet prove native coding-agent autonomy or an independent live model auditor.

## Non-goals in Act 1

Act 1 has no Cursor, Codex, Claude, or other provider invocation; native
write-capable executor; model auditor; UI; browser verification; network or
remote Git action; credential isolation; capability broker; or modification of
the accepted Neon Serpents archive. The fixture executor and fixture auditor are
test adapters, not production claims.

## Constitutional invariants

1. The mission and ordered gate plan become immutable when a session is
   created. Their canonical fingerprints are embedded in every persisted state.
2. No protocol API appends, removes, reorders, or rewrites gates.
3. Gate count is fixed at creation, is non-zero, and cannot exceed four.
4. The Build Week plan constructor accepts exactly three gates.
5. Executor autonomy inside a gate is not admitted command by command. Act 1
   models only the gate's start and the resulting material checkpoint.
6. A gate can end only after a durable, typed material checkpoint has been
   captured and audited.
7. Auditor input is limited to the immutable mission, exact current gate
   contract, material checkpoint, and contract-required evidence declaration.
8. Executor transcript and executor self-justifying narrative are not auditor
   inputs. The test-auditor API deliberately has no such parameters.
9. Every finding must cite an existing clause ID in the current gate contract.
10. An uncited or unknown-clause finding is rejected and cannot become repair
    authority.
11. Verdict strings are exactly `PASS`, `FIX_REQUIRED`, `BLOCKED`, and
    `INCONCLUSIVE`.
12. `INCONCLUSIVE` always enters `AWAITING_HUMAN`; it never advances a gate.
13. Only the pure reducer performs state transitions.
14. A gate contract fixes its repair budget to zero or one, and the reducer can
    authorize at most one repair.
15. Repair authority contains exactly the enforceable finding IDs and bounded
    surfaces accepted from the initial `FIX_REQUIRED` verdict.
16. A gate can receive at most one re-audit, bound to execution attempt 1.
17. A non-PASS re-audit enters `AWAITING_HUMAN`; it can never authorize another
    repair.
18. Mission or contract change requires a new human-authorized session. There
    is no in-session contract-change transition.
19. Neither executor nor auditor can declare final success. A final gate PASS
    enters human review.
20. Final acceptance is a fingerprinted, durable, write-once human disposition.
    Only that disposition transitions final review to `COMPLETED`.

## Trust boundaries and authority

The executor will eventually own ordinary repository exploration, local edits,
shell, npm, tests/build, local Git, and its own diagnosis inside a work gate.
Those commands are outside command-level Admissible admission. Act 1 does not
implement that executor; its fixture can only write predefined bytes.

The protocol-side checkpoint boundary, not the executor, mints checkpoint
identity. It computes the sorted material-tree hash, observes Git HEAD and
porcelain status, runs only verification argv frozen in the gate contract, and
stores bounded stdout/stderr artifacts with byte counts and SHA-256 hashes. It
captures the material tree and Git observations before and after verification;
any mutation rejects the checkpoint. Artifact output must be stored outside the
target repository.

`capture_checkpoint` returns a transient, single-use boundary-issued capture
object. The boundary privately registers its exact in-process object identity,
independent of Python equality and hashing, with its session, gate, attempt,
and checkpoint fingerprint. A weak identity record verifies that the stored
weak reference still resolves to that same object, so object-ID reuse cannot
transfer authority. The object itself carries no transferable marker or
reusable issuance credential. The reducer accepts only that registered exact
object when recording a fresh checkpoint; a plain `Checkpoint`, including one
reconstructed from serialized state, is not fresh capture authority. The
identity is neither persisted nor recreated on restart. This is an ordinary
non-cryptographic in-process API authority boundary, not protection against
arbitrary Python memory modification or hostile interpreter introspection. The
persisted `Checkpoint` remains self-validating and restart-reconstructible from
its fingerprinted data.

The auditor has authority to classify a checkpoint, not to alter the mission,
gate plan, repository, or session. A verdict is accepted only when its session,
gate, checkpoint fingerprint, clause citations, and evidence references all
match current durable authority. A `PASS` with a blocking finding,
`FIX_REQUIRED` without an enforceable repair finding, `BLOCKED` without a human
escalation finding, or contradictory `INCONCLUSIVE` is malformed and rejected.

Only the reducer converts accepted facts into transitions. Executor prose,
auditor narrative, and in-memory adapter state are never transition authority.

## Frozen protocol types

`Mission` contains its schema, stable ID, specification, and canonical
fingerprint. `GatePlan` contains its schema, immutable mission fingerprint,
ordered `GateContract` tuple, and plan fingerprint. Each gate contract fixes its
stable ID, objective, finite stable clause IDs, required evidence kinds,
declared verification argv, repair budget, and contract fingerprint.

`Checkpoint` contains its schema, session and gate IDs, execution attempt index
(0 or 1), sorted material-tree hash, Git HEAD when present, exact porcelain
status, typed evidence records, hashed artifact references, and a protocol-minted
checkpoint fingerprint.

`AuditFinding` binds a stable finding ID to the exact gate and checkpoint, cites
one gate clause, assigns blocking or warning severity, states a concise observed
defect, cites checkpoint evidence, and supplies either a bounded repair surface
or an explicit human-escalation requirement when blocking. `AuditVerdict` binds
the exact session, gate, checkpoint, auditor invocation identity, closed verdict,
findings, and verdict fingerprint.

All serialized objects reject missing and unknown fields. All nested
fingerprints and whole-state invariants are revalidated during disk
reconstruction.

## State transitions

The phase vocabulary is:

`READY_FOR_GATE`, `GATE_EXECUTING`, `CHECKPOINT_CAPTURED`, `AUDITING`,
`REPAIR_AUTHORIZED`, `REPAIR_EXECUTING`, `REAUDITING`, `GATE_PASSED`,
`AWAITING_HUMAN`, and `COMPLETED`.

Straight pass:

```text
READY_FOR_GATE -> GATE_EXECUTING -> CHECKPOINT_CAPTURED -> AUDITING
  -> GATE_PASSED -> READY_FOR_GATE (next predefined gate)
  -> AWAITING_HUMAN (after the final predefined gate)
```

One bounded repair:

```text
AUDITING -> FIX_REQUIRED/REPAIR_AUTHORIZED -> REPAIR_EXECUTING
  -> CHECKPOINT_CAPTURED(attempt 1) -> REAUDITING -> GATE_PASSED
```

Hard boundaries:

```text
initial BLOCKED or INCONCLUSIVE -> AWAITING_HUMAN
initial FIX_REQUIRED with repair budget 0 -> AWAITING_HUMAN
post-repair verdict other than PASS -> AWAITING_HUMAN
```

There is no event for dynamic gate creation, implicit retry, second repair,
second re-audit, contract mutation, or promotion of `INCONCLUSIVE` to `PASS`.

## Checkpoint semantics

The material checkpoint is the only executor output that may enter audit. Its
tree hash is calculated over sorted repository-relative paths, each file's
exact SHA-256, and byte count, excluding Git administrative metadata whether a
`.git` entry is a directory or file (including nested worktree/submodule
entries); symlinks are refused. Files such as `.gitignore` and `git-notes.txt`
remain material content. Git HEAD and `git status --porcelain=v1
--untracked-files=all` are recorded separately.
Each declared verification command uses `shell=False`, a bounded timeout, the
provider-neutral managed-process containment primitive, and bounded output.
Timeout or unproven process cleanup is typed `INCONCLUSIVE`, not success.

Before any Git or verification command starts, capture validates every identity
used in artifact derivation and precomputes the complete artifact plan. The
caller-supplied lexical artifact root, once created if it was absent, and every
existing component of that path must be normal directories, never symlinks,
junctions, or redirecting reparse points. Artifact paths are canonical relative
paths below that anchored root,
are unique, cannot already exist, and are written exclusively without
overwrite. A capture-created output becomes cleanup responsibility immediately
after exclusive creation, together with its exact filesystem identity; the
root is anchored with its exact non-redirecting directory identity. Before
cleanup deletes an output or an empty capture-created root, it rechecks each
lexical component, redirection status, and exact root/file identity. A
redirection or identity mismatch causes explicit cleanup uncertainty and no
deletion through the replacement target. Windows junction and reparse-point
containment is part of this local-filesystem boundary. Write-stage or later
assembly failure removes only verified capture-owned outputs and any still
identity-matching empty capture-created root. Cleanup uncertainty fails closed.
Invalid identities, redirected roots, or artifact collisions fail before an
evidence directory, artifact, or subprocess is created where avoidable.

A boundary-issued capture result is acceptable to the reducer only once, for
the current session, exact current gate, legal attempt, full required
evidence-kind set, and exact ordered verification-command declaration. An
executor-supplied fingerprint or plain checkpoint is not an input to fresh
checkpoint admission.

## Persistence and restart

`AtomicDelegatedSessionStore` is a sibling store, not a widening of V0
`AtomicSessionStore`. It locks one session authority file, validates the entire
state, enforces compare-and-swap revision advancement, fsyncs a temporary file,
atomically replaces the authority file, attempts directory durability, and then
reconstructs and revalidates the state from disk. A stale revision, malformed
JSON, fingerprint mismatch, unknown field, or invariant violation fails closed.
Post-replace directory-durability failure is reported as a typed committed-but-
uncertain outcome with a visibility check, rather than as a retry-safe
pre-commit failure. Replacement also rejects mission/plan changes, history
rewrites, non-adjacent phases, and any successor of `COMPLETED`. No state held
only in memory grants authority after restart.

## Build Week limits

Delegated sessions support one to four predefined gates. The canonical Build
Week run uses exactly three. Every gate independently fixes a repair budget of
zero or one, while the protocol-wide ceiling remains one repair and one
re-audit per gate. Contract changes, expanded gate count, and final acceptance
remain human boundaries.

## Still unimplemented after Act 1

The following remain separate future acts: a real native-agent execution
boundary; independent live model auditor; credential/capability isolation;
provider integration; UI and browser verification; remote Git governance; and
operational recovery flows at non-final human boundaries. Until those exist,
Act 1 demonstrates deterministic protocol correctness only—not native-agent
autonomy, live audit independence, or production readiness.
