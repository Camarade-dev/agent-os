# Admissible Paired Runner — Milestone 1
## Executable Architecture Specification

Status: `PAIRED_ARCHITECTURE_SPECIFICATION_VERIFIED`

This is the provider-free, pure data-model boundary for the future paired
runner. It is executable because the typed records, canonical serializer,
fingerprints, identity checks, and parity gate are implemented and unit-tested.
It is not a runtime qualification report.

The implementation starts at commit
`148f12cfa349243e81e180257b359f97cef63218` on
`paired-runner/m1-executable-architecture-spec`. The frozen governing inputs
remain the plan digest
`0a4316efa770550e50b9218e15782e95a1f96c7440a1a9062a3bd80f6cbfbe24` and audit
digest `4802411063a144b6983d64cc2e7ffab0a64665f4fcd9a88cf2c04c3d8809c4ab`.

## 1. Scope and non-goals

This milestone covers ARCH-02, ARCH-04, ARCH-05, EXEC-01 through EXEC-05,
BASE-01, BASE-02, and FAIR-01 through FAIR-07 at the strongest status
supported by pure artifacts and tests. The exact frozen namespace is
`admissible.paired_runner`.

The package contains immutable typed records and deterministic comparison
logic. It does not:

- launch/contact a model, provider, Codex, Cursor, or app-server;
- implement transport, continuation, process supervision, policy, owner
  authorization, broker, witness, mint, or authority consumption;
- implement a filesystem or command tool, effect executor, or model-facing
  mutation path;
- install, benchmark, prepare a real task, or produce a real result;
- import/revive `admissible.runner`, `long_run`, `high_autonomy`, or historical
  pairing modules;
- touch V14–V18 evidence, preparation, runtime, installation, or terminal
  artifacts.

`EffectReservation` and `EffectReceipt` are future boundary representations,
not effect operations. No record in M1 performs the next lifecycle arrow.

### File-by-file implementation plan

The following plan was recorded during the initial repository audit before any
M1 implementation file was written:

| File | Planned responsibility | Boundary preserved |
|---|---|---|
| `admissible/paired_runner/canonical.py` | Canonical UTF-8 JSON, strict parsing, domain-separated fingerprints | No I/O or runtime calls |
| `admissible/paired_runner/schemas.py` | Version constants and machine-readable schema descriptors | No prose-only schema |
| `admissible/paired_runner/identities.py` | Component, run, and session identity binding | No mint or durable store |
| `admissible/paired_runner/specification.py` | Immutable experiment, proposal, decision, reservation, receipt, budget, intervention, evaluator, terminal, and comparative records | No policy, effect, transport, or evaluator execution |
| `admissible/paired_runner/comparison.py` | Fail-closed parity normalization and stable mismatch reports | No hidden field selection |
| `admissible/paired_runner/__init__.py` | Exact namespace exports | No historical imports |
| `tests/test_admissible_paired_runner_m1*.py` | Pure invariant, artifact, and 83-requirement completeness tests | Repository-local only |
| `implementation/M1_*.{md,json}` | Architecture, schema, allowlist, and validation outputs | No M2 artifact |
| `implementation/ADR_REGISTER.md` and the in-scope matrix records | Evidence and status updates only | No ADR weakening or out-of-scope status change |

## 2. Relationship to all twelve ADRs

The M0 register remains authoritative. M1 adds evidence and clarifications,
never a weakened ADR.

| ADR | M1 consequence | Remaining boundary |
|---|---|---|
| ADR-001 | One model, executable/digest, and transport identity are required. | Provider-free transport and integration are later. |
| ADR-002 | One typed grammar identity and the four initial tool names are required. | Tool execution is M2. |
| ADR-003 | CanonicalProposal carries all required causal/run/session/input identities before effect. | Durable publication is M2. |
| ADR-004 | ModeDecision is the unique A/B decision interface; reservation/receipt types are shared. | Physical substrate is M2/M5. |
| ADR-005 | Common observations use common types; governance fields are confined to condition/decision records. | Runtime observation is M2/M3/M7. |
| ADR-006 | Initial state, environment, toolchain, common security policy, and budgets are explicit parity inputs. | Physical snapshots/isolation are M7. |
| ADR-007 | Governed mode requires an explicit future decision reference; no broker/owner code is used. | Disposable authority integration is M4. |
| ADR-008 | ALLOW/REFUSE/TERMINATE_RUN/REQUIRE_CONTINUATION are explicit governed values. | Policy execution is M4. |
| ADR-009 | Run/session identities carry condition, continuation index, predecessor, and causal binding. | Durable restart is M3. |
| ADR-010 | EvaluatorSpecification and TerminalManifest separate process result, model claim, repository state, and acceptance. | Evaluator is M6. |
| ADR-011 | V14–V18 are not inputs, fixtures, imports, or mutable state. | Historical roots remain immutable. |
| ADR-012 | All M1 logic is fresh under the selected namespace; no historical import closure is used. | Future extraction needs a new provenance record. |

## 3. Component diagram and exact decision boundary

```text
ExperimentSpecification
  (same task/snapshot/model/executable/transport/grammar/environment/toolchain/
   policy/effect-executor/evaluator/budgets)
        |
        v
Shared future ModelTransport
        |
        v
CanonicalProposal -- durable proposal-before-effect boundary (M2)
        |
        v
ModeDecision  <----- the only causal A/B boundary
   |                         |
   | DIRECT                  | GOVERNED
   | DIRECT_EXECUTION        | ALLOW/REFUSE/TERMINATE_RUN/
   | prerequisite NONE        | REQUIRE_CONTINUATION
   | no Admissible decision   | prerequisite ADMISSIBLE_DECISION
   +------------+------------+
                |
                v
Shared future EffectExecutor (M2) -> EffectReceipt -> state/evaluator/archive
```

DIRECT cannot contain an Admissible decision prerequisite. GOVERNED cannot use
`DIRECT_EXECUTION`; every governed decision has a future decision reference.
Only direct execution or governed ALLOW can form an EffectReservation. This is
representation/invariant checking, not a policy engine or executor.

## 4. Object lifecycle and causal-order contract

```text
RunIdentity
  -> SessionIdentity (run + condition + continuation predecessor)
  -> CanonicalProposal (proposal-before-effect)
  -> ModeDecision
  -> EffectReservation (only permitted decision)
  -> EffectReceipt (classified outcome)
  -> TerminalManifest
two condition manifests + parity report -> ComparativeManifest
```

`RunIdentity` binds one experiment and condition. `SessionIdentity` binds one
run and condition and cannot cross either boundary. A proposal binds turn,
tool, canonical arguments, scope, working root, causal predecessor, wall and
monotonic observations, and all common component identities. A reservation
binds exactly one proposal, one mode-decision fingerprint, and one future
shared effect-executor identity. A receipt never carries task acceptance.

`EffectReceipt.status` distinguishes `PROPOSED`, `RESERVED`, `STARTED`,
`COMPLETED`, `REFUSED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, and `AMBIGUOUS`.
Refusal cannot simultaneously represent an executed effect. A terminal
manifest requires independent evaluator basis; process exit zero is not
acceptance.

## 5. Schema catalog

`implementation/M1_SCHEMA_CATALOG.json` is the machine-readable catalog. It
contains 19 version-1 descriptors with schema ID/version, implementation
type, canonical domain, fingerprint domain, required fields, and owner:

```text
Fingerprint, IdentityReference, RunIdentity, SessionIdentity,
ConditionConfiguration, AllowedConditionDifferences, BudgetState,
ClockObservation, CausalPredecessor, ExperimentSpecification,
CanonicalProposal, ModeDecision, EffectReservation, EffectReceipt,
HumanInterventionRecord, EvaluatorSpecification, TerminalManifest,
ComparativeManifest, ParityReport
```

Every persisted record contains `schema_id` and integer `schema_version`.
`from_dict` checks exact fields; nested records are also typed. No required
concept is represented by a generic unvalidated dictionary.

## 6. Canonicalization contract

`canonical.py` is the only M1 byte serializer. It accepts null, booleans,
UTF-8 strings, signed 64-bit integers, arrays, and string-keyed objects.
It emits UTF-8 JSON with sorted keys, no insignificant whitespace, and
`,:` separators. Normative arrays retain order; set-like typed lists are
sorted/unique before serialization. Floats, NaN, infinities, bytes, dates,
tuples, sets, custom objects, wide integers, invalid UTF-8, and implicit type
coercions are refused. Raw JSON duplicate keys are refused before semantic
interpretation. `parse_canonical_json` compares original bytes with a fresh
canonical serialization and rejects pretty/reordered/non-canonical input.

Prompt bytes use a canonical hex wrapper via `fingerprint_bytes`, preserving
exact bytes without implicit newline or datetime behavior. No locale,
timezone, environment, or filesystem formatting affects these bytes.

## 7. Fingerprint contract

Every fingerprint is a self-describing triple:

```json
{"algorithm":"sha256","domain":"...","value":"64 lowercase hex characters"}
```

The digest frames a fixed protocol prefix, domain length/domain, payload
length, and canonical payload. Thus identical payloads in different object
domains cannot share an identity accidentally. Object fingerprints cover the
body excluding the derived fingerprint field. Content and instance semantics
are explicit: component references state `CONTENT` or `INSTANCE`; run,
session, proposal, decision, reservation, receipt, terminal, and comparative
fingerprints are instance identities. Fingerprints are re-derived during
validation and change for every normative-field mutation.

Timestamps/run IDs appear only in explicitly instance/causal records. Wall
time is integer Unix milliseconds. Monotonic time is integer nanoseconds or
the explicit `FUTURE_RUNTIME_MONOTONIC_NS` placeholder whose absent-value
semantics are documented and not confused with zero.

## 8. Required data types and bindings

`ExperimentSpecification` binds task prompt, initial state, model,
executable/digest, transport, tool grammar, environment, dependency/toolchain,
common filesystem/network/process policy, the shared effect executor,
evaluator, common budgets, allowed differences, condition, and run identity.

`CanonicalProposal` binds schema/version, run/condition/session/turn/proposal,
tool and canonical arguments, working-root/scope, causal predecessor, wall and
monotonic observations, model/transport/prompt/tool-grammar identities, and
the constant pre-effect marker `PROPOSAL_BEFORE_EFFECT`.

`BudgetState` has integer cumulative counters for sessions, turns, proposals,
effects, commands, wall time (ms), model-active time (ms), output bytes,
retries, continuations, and human interventions. Limits are integer or
explicit null (unbounded); usage is non-null and monotone. Negative increments,
limit crossings, and signed 64-bit overflow are refused.

`HumanInterventionRecord` binds actor class, reason, timing, affected
run/session/proposal, allowed policy category, and `NONE`/`QUALIFY`/`INVALIDATE`
comparability disposition. Unallowed category `NONE` must invalidate.

`EvaluatorSpecification` binds evaluator/version, requirements/scope/test-plan
fingerprints, environment, and mandatory independence/acceptance-separation
flags. `TerminalManifest` reconciles physical repository state, proposal and
receipt ledgers, budgets, evaluator, model claim, process result, and task
acceptance without trusting the model. `ComparativeManifest.create` accepts
only two typed condition specifications and a passing `ParityReport`; it
derives one common-experiment fingerprint and requires exactly two distinct
runs, one DIRECT and one GOVERNED, with the parity report bound to those
specifications. Deserialization also requires the common-experiment fingerprint
domain.

## 9. Exact allowed A/B differences

`implementation/M1_ALLOWED_CONDITION_DIFFERENCES.json` is the sole semantic
allowlist:

```text
condition.admissible_decision_required
condition.condition_id
condition.governance_evidence
condition.owner_delegation_required
```

It explicitly lists the two non-semantic instance-binding paths:

```text
run_identity.condition_id
run_identity.run_id
```

The latter paths are not causal input differences: distinct run instances
must be bound to their respective conditions. They are listed so parity has
no hidden ignore rule. Model, executable, prompt, initial state, transport,
tool grammar, environment, dependencies/toolchain, common policy, evaluator,
budgets, scope, effect executor, and safety confinement are not allowed
differences.

## 10. Parity-gate algorithm and refusal taxonomy

`check_parity` parses/validates both specs and the exact allowlist, requires
one DIRECT and one GOVERNED condition, requires one experiment ID and distinct
run IDs, then recursively compares every value in each explicit
`normative_dict`. Only derived object fingerprints are omitted there. Lists
remain ordered. The only skipped paths are the manifest paths. Missing,
extra, or changed values produce stable paths such as
`executable_digest.value` or `condition.governance_evidence`. Mismatches are
sorted by path/category/value and the input objects are never mutated.

Structured reports use these codes:

```text
CONDITION_PAIR_INVALID
UNRELATED_EXPERIMENT_IDS
RUN_ID_REUSE
UNKNOWN_DIFFERENCE_CATEGORY
MALFORMED_DIFFERENCE_MANIFEST
MALFORMED_NON_CANONICAL_INPUT
UNAUTHORIZED_DIFFERENCE
NONE (passing report)
```

Canonical errors are `CanonicalizationError`, `DuplicateKeyError`, and
`NonCanonicalEncodingError`; typed schema errors fail with `ValueError`;
`require_parity` raises `ParityRefused` on any non-passing report. All paths
fail closed and never suggest a dangerous retry.

## 11. Deferred fields and why M2 has not begun

Deferred are actual model transport/events, proposal durability and fsync,
effects/process/output/cancellation, multi-session restart and live budgets,
owner/broker expiry/revocation/policy, physical snapshots and cache/network
isolation, installed qualification, evaluator commands, terminal archive, and
the real task/benchmark. M2 would create effect supervision, filesystem
mutation tools, or command execution, which this assignment forbids. M1 stops
at the pure representation boundary.

## 12. Provenance and threat model

No runtime module is imported. The fresh standard-library implementation was
informed by the following M0-approved references; no source code was copied
into the package:

| M1 design area | Inspected provenance | Treatment in M1 |
|---|---|---|
| Canonical bytes, strict JSON, and fingerprints | M0 current candidate `ab3e712` `admissible/capsule/common.py` (SHA-256 `db39f0d1e2e78d8241eccba40c4ab52c0c0a5a7b9143ae4e859791366f1a0eec`); strong canary `fdb009a` `admissible/capsule/common.py` | Fresh stricter implementation under `admissible.paired_runner.canonical` |
| Exact-key, versioned records and terminal separation | M0 current candidate `ab3e712` `admissible/capsule/models.py`, `verification.py`, and `finalizer.py`; strong canary equivalents at `fdb009a` | Fresh dataclasses and exact-key `from_dict` validators |
| Component identity and dynamic tool grammar | Strong canary `fdb009a` `admissible/capsule/execution_authority.py` and `host_codex_backend.py`; M0 current grammar schema `admissible/capsule/protocol_schemas/DynamicToolCallParams.json` | Identity and grammar are represented as content identities; no transport or tool is launched |
| Causal/pre-effect ordering and receipt concepts | Strong canary `fdb009a` capsule publication/verification records and M0 ADR-003/004/010 | Reduced to pure proposal, decision, reservation, receipt, and terminal invariants |

These references are provenance only; no broker, witness, transport, finalizer,
historical runner, Cursor path, or production root is used. The full source
digests and classifications remain in M0 `SOURCE_OF_TRUTH.json` and its
provenance table.

The pure layer protects against serializer ambiguity, duplicate keys, numeric
coercion, schema drift, unknown fields, cross-run/session/condition reuse,
proposal/effect confusion, refusal-as-execution, process-success-as-acceptance,
hand-picked parity, unauthorized input differences, and input mutation by the
checker. It does not protect against a compromised later runtime that ignores
the types, forges observations, tampers with workspaces, or bypasses an
effect substrate. It is a precondition checker, not an authority boundary.

## 13. Requirement disposition

| ID | Status | Physical support and limit |
|---|---|---|
| ARCH-02 | `DESIGNED` | One future lifecycle is specified; no connected runtime. |
| ARCH-04 | `DESIGNED` | Shared transport/proposal/executor identities are mandatory; physical reuse is later. |
| ARCH-05 | `VERIFIED_UNIT` | ModeDecision tests prove one direct/governed boundary; no runtime call graph. |
| EXEC-01 | `VERIFIED_UNIT` | Executable identity/digest and altered-digest parity test; no executable launch. |
| EXEC-02 | `VERIFIED_UNIT` | Pre-effect proposal marker and reservation binding; durable publication is M2. |
| EXEC-03 | `DESIGNED` | Governed reservation requires ALLOW; no policy gate/mutation. |
| EXEC-04 | `DESIGNED` | Direct representation shares proposal schema; no direct runner. |
| EXEC-05 | `DESIGNED` | One executor identity is bound; executor absent until M2. |
| BASE-01 | `DESIGNED` | DIRECT is a first-class condition, not an operator log; physical runner is M5. |
| BASE-02 | `VERIFIED_UNIT` | Full non-governance parity comparison and mutation tests; physical delivery is M7/M8. |
| FAIR-01 | `VERIFIED_UNIT` | Exact byte prompt fingerprint and mutation refusal. |
| FAIR-02 | `VERIFIED_UNIT` | Required initial-state fingerprint and mutation refusal. |
| FAIR-03 | `VERIFIED_UNIT` | Required dependency/toolchain identity and mutation refusal. |
| FAIR-04 | `VERIFIED_UNIT` | Model/executable/transport/tools/policy identities and mutations. |
| FAIR-05 | `VERIFIED_UNIT` | Typed common budgets, monotonic counters, mutation refusal. |
| FAIR-06 | `VERIFIED_UNIT` | Exact allowlist rejects unknown/broadened categories. |
| FAIR-07 | `VERIFIED_UNIT` | Deterministic fail-closed report compares every remaining field. |

## 14. Final M1 boundary

This specification does not claim `VERIFIED_INTEGRATION` or
`VERIFIED_INSTALLED_PATH`. It records no provider-specific runtime behavior,
does not authorize effects, and does not begin Milestone 2.
