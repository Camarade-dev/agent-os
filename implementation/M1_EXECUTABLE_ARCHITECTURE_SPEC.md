# Admissible Paired Runner — Milestone 1
## Executable Architecture Specification

Status: `M1_SECOND_BOUNDED_REPAIRS_VERIFIED`

This is the provider-free, pure data-model boundary for the future paired
runner. It is executable because the typed records, canonical serializer,
fingerprints, identity checks, grammar manifest, causal reconciliation paths,
and parity gate are implemented and unit-tested. It is not a runtime
qualification report.

The second bounded-repair work starts at commit
`41942a3ed3a85d4f47b38a29b9d86368523555cd` on
`paired-runner/m1-terminal-binding-repairs`. The first bounded repair started at
`d480c5eeff848fac1075d861d352228d6e65712f`. The frozen governing inputs remain
the plan digest
`0a4316efa770550e50b9218e15782e95a1f96c7440a1a9062a3bd80f6cbfbe24` and audit
digest `4802411063a144b6983d64cc2e7ffab0a64665f4fcd9a88cf2c04c3d8809c4ab`.

## 1. Scope and non-goals

This milestone covers ARCH-02, ARCH-04, ARCH-05, EXEC-01 through EXEC-05,
BASE-01, BASE-02, and FAIR-01 through FAIR-07 at the strongest status
supported by pure artifacts and tests, including the bounded repairs M1-R01
through M1-R05 and the second bounded repairs M1-R06 through M1-R11. The exact
frozen namespace is `admissible.paired_runner`.

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

### Schema evolution decision

All affected records remain at schema version `1`. M1 records still have no
external or runtime persistence contract; the repository artifacts are
specification fixtures and are regenerated together with the pure validators.

**No pre-repair M1 object is accepted as authoritative.** Every M1 object
produced before this commit is refused, and no mixed old/new definition can
deserialize by accident:

| Pre-repair object | Why it can no longer deserialize |
|---|---|
| `ExperimentSpecification` | exact-key parsing requires the new `tool_grammar` and `evaluator_specification` fields |
| `EffectReceipt` | exact-key parsing requires `tool_name`, `effect_classification`, `tool_request_fingerprint`, `tool_result`, `execution_failure`, and `effect_application` |
| `RunCommandResult` | exact-key parsing requires `process_started` |
| `WriteFileResult` | a written-content fingerprint outside the fixed written-content domain is refused |
| any tool request | a `tool_grammar_fingerprint` outside the grammar-specification domain is refused |
| `CanonicalProposal` | its request must be present in, and cite, the exact typed grammar |
| `TerminalManifest` | it must bind the exact experiment evaluator specification |

`tests/test_admissible_paired_runner_m1_second_repairs.py::PreRepairObjectRejectionTests`
proves the first three rows mechanically. A future runtime persistence contract
must either adopt these exact version-1 definitions before use or issue a new
ADR and consistently increment the affected schema versions.

### File-by-file implementation plan

The following plan was recorded during the initial repository audit before any
M1 implementation file was written:

| File | Planned responsibility | Boundary preserved |
|---|---|---|
| `admissible/paired_runner/canonical.py` | Canonical UTF-8 JSON, strict parsing, domain-separated fingerprints | No I/O or runtime calls |
| `admissible/paired_runner/schemas.py` | Version constants and machine-readable schema descriptors | No prose-only schema |
| `admissible/paired_runner/tool_schemas.py` | Closed typed request/result unions for the four tools, their exact-request validation, and the typed tool-grammar manifest | No tool execution |
| `admissible/paired_runner/identities.py` | Component, run, and session identity binding | No mint or durable store |
| `admissible/paired_runner/specification.py` | Immutable experiment, proposal, decision, reservation, receipt, budget, intervention, evaluator, terminal, and comparative records | No policy, effect, transport, or evaluator execution |
| `admissible/paired_runner/comparison.py` | Fail-closed parity normalization and stable mismatch reports | No hidden field selection |
| `admissible/paired_runner/__init__.py` | Exact namespace exports | No historical imports |
| `tests/test_admissible_paired_runner_m1.py` | Pure tool, binding, lifecycle, and parity tests | Repository-local only |
| `tests/test_admissible_paired_runner_m1_oracle.py` | Independently declared normative receipt/terminal fixture tables and the exhaustive sweeps they drive | Never reads the implementation matrix to decide an expected answer |
| `tests/test_admissible_paired_runner_m1_second_repairs.py` | Refusal and closure tests for M1-R06 through M1-R11 plus the four-tool two-condition typed chain | No effect, process, provider, or authority |
| `tests/test_admissible_paired_runner_m1_artifacts.py` and `_completeness.py` | Canonical artifact and 83-requirement status tests | Repository-local only |
| `implementation/M1_*.{md,json}` | Architecture, schema, allowlist, and validation outputs | No M2 artifact |
| `implementation/ADR_REGISTER.md` and the in-scope matrix records | Evidence and status updates only | No ADR weakening or out-of-scope status change |

## 2. Relationship to all fourteen ADRs

The M0 register remains authoritative. M1 adds evidence and clarifications,
never a weakened ADR.

| ADR | M1 consequence | Remaining boundary |
|---|---|---|
| ADR-001 | One model, executable/digest, and transport identity are required. | Provider-free transport and integration are later. |
| ADR-002 | One typed ToolGrammarSpecification binds the four tool names, their exact request/result schemas, versions, effect classifications, and descriptor fingerprints. | Tool execution is M2. |
| ADR-003 | CanonicalProposal carries all required causal/run/session/input identities before effect. | Durable publication is M2. |
| ADR-004 | ModeDecision is the unique A/B decision interface; reservation/receipt types are shared. | Physical substrate is M2/M5. |
| ADR-005 | Common observations use common types; governance fields are confined to condition/decision records. | Runtime observation is M2/M3/M7. |
| ADR-006 | Initial state, environment, toolchain, common security policy, and budgets are explicit parity inputs. | Physical snapshots/isolation are M7. |
| ADR-007 | Governed mode requires an explicit future decision reference; no broker/owner code is used. | Disposable authority integration is M4. |
| ADR-008 | ALLOW/REFUSE/TERMINATE_RUN/REQUIRE_CONTINUATION are explicit governed values. | Policy execution is M4. |
| ADR-009 | Run/session identities carry condition, continuation index, predecessor, and causal binding. | Durable restart is M3. |
| ADR-010 | The experiment binds one exact EvaluatorSpecification; TerminalManifest must be issued by that evaluator and keeps process result, model claim, repository state, and acceptance separate. | Evaluator execution is M6. |
| ADR-011 | V14–V18 are not inputs, fixtures, imports, or mutable state. | Historical roots remain immutable. |
| ADR-012 | All M1 logic is fresh under the selected namespace; no historical import closure is used. | Future extraction needs a new provenance record. |
| ADR-013 | The five bounded M1 repairs are pure, version-1, typed, fail-closed corrections. | The repair boundary does not authorize M2. |
| ADR-014 | The six second bounded M1 repairs add the typed grammar manifest, the exact evaluator binding, the typed reconciliation paths, the effect-aware receipt, and exact request/result validation. | The repair boundary does not authorize M2. |

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
ToolGrammarSpecification (four typed entries)
  -> ExperimentSpecification (binds the grammar and the evaluator specification)
  -> RunIdentity
  -> SessionIdentity (run + condition + continuation predecessor)
  -> CanonicalProposal (proposal-before-effect, typed request proven by the grammar)
  -> ModeDecision
  -> EffectReservation (only a permitting decision)
  -> typed ToolResult (validated against its exact request)
  -> EffectReceipt (effect-aware, authoritatively reconciled)
  -> TerminalManifest (exact evaluator specification)
two condition manifests + parity report -> ComparativeManifest
```

`RunIdentity` binds one experiment and condition. `SessionIdentity` binds one
run and condition and cannot cross either boundary. A proposal binds turn,
one typed tool request, scope, working root, causal predecessor, wall and
monotonic observations, and all common component identities. Its exact
experiment-specification fingerprint is mandatory. A reservation binds
exactly one proposal, one mode-decision fingerprint, the exact experiment
specification, and that specification's effect-executor identity. A receipt
never carries task acceptance.

The four tools each have a versioned request and result record. Their exact
fields, required/optional semantics, relative POSIX path representation,
bounds, effect classification, result representation, exact-request binding,
and request/result fingerprint domains are machine-readable in the schema
catalog. Unknown fields, cross-tool records, and the former generic
`read_file` payload are refused.

### Structural validation versus authoritative typed reconciliation

Two different guarantees are deliberately separated, and only the second is
authoritative for a future execution decision:

| Path | What it proves | What it cannot prove |
|---|---|---|
| `validated()` | the object is internally consistent and its own fingerprint re-derives from its own fields | nothing about the objects it names |
| `validate_for_specification()` | the object belongs to one exact experiment specification | nothing about the proposal, decision, or result it names |
| `ModeDecision.validate_for_proposal()` | the decision was taken on exactly this proposal | — |
| `EffectReservation.validate_for_decision()` | exact specification, proposal ID and fingerprint, proposal-for-specification validity, decision fingerprint, decision-for-proposal validity, effect permission, executor identity, and pre-start state | — |
| `EffectReceipt.validate_for_causal_chain()` | the whole chain above plus the exact tool name, effect classification, typed request, typed result, and reservation | — |

A self-consistent object restored from bytes can always recompute its own
fingerprint, so structural validation alone is never a causal proof. **A
reservation restored from bytes is not authoritative for execution until
`validate_for_decision` succeeds, and a receipt is not authoritative until
`validate_for_causal_chain` succeeds.** A future runtime must call the typed
reconciliation before acting on a restored object.

### Effect-aware receipt contract

`EffectReceipt.status` distinguishes `PROPOSED`, `RESERVED`, `STARTED`,
`COMPLETED`, `REFUSED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, and `AMBIGUOUS`.
A receipt binds the exact tool name, the effect classification implied by that
tool, the exact typed request fingerprint, and — only where the lifecycle state
has one — a typed `ToolResult` or a typed execution-failure class.

`RECEIPT_STATE_MATRIX` is indexed by lifecycle state, and process-exit policy
and reconciliation are resolved by lifecycle state **together with effect
classification** through `receipt_process_exit_policy` and
`receipt_reconciliation_required`:

| State | Reservation | started/completed/executed | Result channel | Exit code (`run_command`) | Exit code (file tools) | Effect application |
|---|---|---|---|---|---|---|
| `PROPOSED` | forbidden | F/F/F | none | forbidden | forbidden | `NOT_APPLIED` |
| `RESERVED` | required | F/F/F | none | forbidden | forbidden | `NOT_APPLIED` |
| `STARTED` | required | T/F/F | none | forbidden | forbidden | `PARTIAL_OR_UNKNOWN` |
| `COMPLETED` | required | T/T/T | successful typed result | required | forbidden | `APPLIED` |
| `REFUSED` | allowed | F/F/F | none or typed refusal | forbidden | forbidden | `NOT_APPLIED` |
| `FAILED` | required | T/T/F | failed typed result or typed execution failure | allowed | forbidden | `PARTIAL_OR_UNKNOWN` |
| `CANCELLED` | required | T/T/F | none or typed execution failure | allowed | forbidden | `PARTIAL_OR_UNKNOWN` |
| `TIMED_OUT` | required | T/F/F | none or typed execution failure | allowed | forbidden | `PARTIAL_OR_UNKNOWN` |
| `AMBIGUOUS` | required | T/F/F | none | forbidden | forbidden | `PARTIAL_OR_UNKNOWN` |

Consequences that the generic matrix previously could not express:

- a completed `read_file`, `list_files`, or `write_file` neither requires nor
  accepts a process exit code; only `run_command` has process-exit semantics,
  and a `COMPLETED` `run_command` receipt must agree with its typed result's
  exit code;
- pre-effect states cannot carry a tool result, and a typed result always
  requires the reservation that authorized the effect;
- `REFUSED` cannot claim an executed effect;
- `COMPLETED` must bind a successful typed result for the exact request;
- `FAILED` must bind a failed typed result or an explicitly typed execution
  failure;
- `AMBIGUOUS` can claim neither completion nor a known successful result;
- any partial or unknown application of a `FILE_MUTATION` or
  `PROCESS_EXECUTION` effect requires reconciliation and forbids replay;
- task acceptance remains absent from every receipt.

### Exact request/result validation

Each result type implements a pure `validate_for_request`, and the
authoritative receipt reconciliation calls it:

| Result | Exact binding |
|---|---|
| `ListFilesResult` | exact request fingerprint; entry count within the request limit; entries sorted, unique, and inside the requested path; a non-recursive request admits direct children only; truncation only at the request entry bound |
| `ReadFileResult` | exact request fingerprint; retained lines within the request line bound; `bytes_read` equal to the encoded content length; truncation only at the line bound or the content cap; no content for refused or failed outcomes |
| `WriteFileResult` | exact request fingerprint; `bytes_written` equal to the UTF-8 byte length of the exact requested content; written-content fingerprint equal to the fixed-domain fingerprint of those exact bytes; any other fingerprint domain refused; refused or failed outcomes claim no mutation |
| `RunCommandResult` | exact request fingerprint; stdout and stderr within the request output bound; truncation only at that bound; process observations only for a started command; `outcome == OK` means the tool executed the exact command, not that the command exited zero |

`TerminalManifest` uses `TERMINAL_STATE_MATRIX`: `ACCEPTED` and `REJECTED`
require complete reconciliation and an independent evaluator disposition;
`INCONCLUSIVE` and `NOT_EVALUATED` are explicitly non-final and cannot claim
completed reconciliation. Process result, model completion, and task
acceptance remain separate fields.

`ComparativeManifest.create` accepts typed DIRECT and GOVERNED terminal
manifests, not terminal fingerprints. It validates each terminal against its
exact run and specification, requires distinct terminal fingerprints and
final reconciled dispositions, and binds the exact parity report. Deserialized
manifests retain typed terminals; `validate_for_specifications` is the typed
reconciliation path for final closure.

## 5. Schema catalog

`implementation/M1_SCHEMA_CATALOG.json` is the machine-readable catalog. It
contains 29 version-1 descriptors with schema ID/version, implementation
type, canonical domain, fingerprint domain, required fields, and owner. The
eight tool descriptors additionally declare field types, optional fields,
path representation, bounds, effect classification, result representation, and
the exact-request binding their result must satisfy:

```text
Fingerprint, IdentityReference, RunIdentity, SessionIdentity,
ConditionConfiguration, AllowedConditionDifferences, BudgetState,
ClockObservation, CausalPredecessor, ExperimentSpecification,
CanonicalProposal, ModeDecision, EffectReservation, EffectReceipt,
HumanInterventionRecord, EvaluatorSpecification, TerminalManifest,
ComparativeManifest, ToolGrammarEntry, ToolGrammarSpecification, ParityReport,
ListFilesRequest, ListFilesResult, ReadFileRequest, ReadFileResult,
WriteFileRequest, WriteFileResult, RunCommandRequest, RunCommandResult
```

### Tool-grammar specification

`ToolGrammarSpecification` is the machine-verifiable grammar manifest. It binds
its own schema and version, a grammar ID and grammar version, exactly the four
frozen tool names, and one `ToolGrammarEntry` per tool. Each entry binds the
exact request schema ID and version, the exact result schema ID and version,
the effect classification, and the fingerprints of the exact machine-readable
descriptors that carry those schemas' fields and bounds. Entry validation
recomputes both descriptor fingerprints from the catalog, so a forged
descriptor fingerprint, a forged schema version, or a forged effect
classification is refused.

`ExperimentSpecification` embeds the grammar and requires
`tool_grammar_identity` to be reconstructible from the grammar's exact
contents, so the label identity can no longer stand in for the grammar.
`CanonicalProposal.create` and `validate_for_specification` prove that the
request schema is present in that exact grammar, that its version is permitted,
that the cited grammar fingerprint is exact, and that the tool name and effect
classification match the grammar entry. Requests may only cite a fingerprint in
the grammar-specification domain, so an opaque label is refused before any
comparison. `check_parity` compares the entire grammar specification between A
and B.

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
executable/digest, transport, the typed tool-grammar specification and its
derived grammar identity, environment, dependency/toolchain, common
filesystem/network/process policy, an authorized working root and scope, the
shared effect executor, the typed evaluator specification and its derived
evaluator identity, common budgets, allowed differences, condition, and run
identity.

The evaluator component identity and the evaluator specification are distinct
records with explicit roles. `evaluator_identity` is a named `CONTENT` identity
whose material is the evaluator specification, so it names the evaluator
without hiding it; `evaluator_specification` is the strict typed object that
binds evaluator ID, version, requirements, scope, test plan, environment, and
the mandatory independence and acceptance-separation flags. The evaluator's
environment must equal the experiment environment.
`TerminalManifest.validate_for_specification` compares the terminal's
`evaluator_specification_fingerprint` with the experiment's evaluator
fingerprint — one fingerprint domain on both sides — so a terminal issued by
any other evaluator is refused, and `ComparativeManifest` inherits that binding
for both runs.

`CanonicalProposal` binds schema/version, run/condition/session/turn/proposal,
the exact experiment-specification fingerprint, a typed tool request,
working-root/scope, causal predecessor, wall and monotonic observations,
model/transport/prompt/tool-grammar identities, and the constant pre-effect
marker `PROPOSAL_BEFORE_EFFECT`. `validate_for_specification` is a pure
fail-closed proof of every one of those bindings, including prompt content and
membership of the request in the exact typed grammar.

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
flags. `TerminalManifest` reconciles physical repository state, proposal and receipt
ledgers, budgets, the exact experiment evaluator, model claim, process result,
and task acceptance without trusting the model. `ComparativeManifest.create` accepts
two typed condition specifications, two typed terminal manifests, and a
passing `ParityReport`; it derives one common-experiment fingerprint and
requires exactly two distinct runs, one DIRECT and one GOVERNED, with each
terminal bound to its corresponding specification and the parity report bound
to those specifications. Deserialization retains the terminal objects and
requires `validate_for_specifications` for typed final reconciliation.

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
| Exact-key, versioned records and terminal separation | M0 current candidate `ab3e712` `admissible/capsule/models.py`, `verification.py`, and `finalizer.py`; strong canary equivalents at `fdb009a` | Fresh dataclasses and exact-key `from_dict` validators plus exhaustive receipt/terminal matrices |
| Component identity and dynamic tool grammar | Strong canary `fdb009a` `admissible/capsule/execution_authority.py` and `host_codex_backend.py`; M0 current grammar schema `admissible/capsule/protocol_schemas/DynamicToolCallParams.json` | Identity and grammar are represented as content identities; the four request/result schemas are fresh and no tool is launched |
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

Every status below is a pure-specification status. No record claims
`VERIFIED_INTEGRATION` or `VERIFIED_INSTALLED_PATH`, and `VERIFIED_UNIT` here
means "unit-verified against the pure M1 objects", never "runtime proven".

| ID | Status | Change | Physical support and limit |
|---|---|---|---|
| ARCH-02 | `DESIGNED` | unchanged | The typed closure chain and its reconciliation paths are specified; no connected runtime. |
| ARCH-04 | `DESIGNED` | unchanged | One typed grammar, proposal bus, and executor identity are mandatory; physical reuse is later. |
| ARCH-05 | `VERIFIED_UNIT` | unchanged | ModeDecision is the sole boundary and now validates against its exact proposal; no runtime call graph. |
| EXEC-01 | `VERIFIED_UNIT` | unchanged | Executable identity/digest binding and parity refusal; no executable launch. |
| EXEC-02 | `DESIGNED` | restored from `VERIFIED_UNIT` | The pure pre-effect canonical form is verified, but the requirement also demands durable pre-effect publication, which is M2. A whole-requirement status must not imply runtime proof. |
| EXEC-03 | `DESIGNED` | unchanged | Only a permitting decision can reserve; no policy gate or mutation. |
| EXEC-04 | `DESIGNED` | unchanged | DIRECT shares the typed chain; no direct runner. |
| EXEC-05 | `DESIGNED` | restored from `VERIFIED_UNIT` | A matching executor identity field is not proof that the effect executor is identical in A and B, and no executor exists yet. |
| BASE-01 | `DESIGNED` | unchanged | DIRECT is a first-class condition, not an operator log; physical runner is M5. |
| BASE-02 | `VERIFIED_UNIT` | unchanged | Full non-governance parity comparison, now including the typed grammar and evaluator. |
| FAIR-01 | `VERIFIED_UNIT` | unchanged | Exact byte prompt fingerprint and mutation refusal. |
| FAIR-02 | `VERIFIED_UNIT` | unchanged | Required initial-state fingerprint and mutation refusal. |
| FAIR-03 | `VERIFIED_UNIT` | unchanged | Required dependency/toolchain/environment identity, including the evaluator environment. |
| FAIR-04 | `VERIFIED_UNIT` | unchanged | Model/executable/transport/typed grammar/policy identities and mutations. |
| FAIR-05 | `VERIFIED_UNIT` | unchanged | Typed common budgets, monotone counters, mutation refusal. |
| FAIR-06 | `VERIFIED_UNIT` | unchanged | Exact allowlist rejects unknown/broadened categories. |
| FAIR-07 | `VERIFIED_UNIT` | unchanged | Deterministic fail-closed report compares every remaining field. |

## 14. Independent-oracle test discipline

`RECEIPT_STATE_MATRIX` and `TERMINAL_STATE_MATRIX` are the objects under test,
so no exhaustive test may read them to decide which rows should pass.
`tests/test_admissible_paired_runner_m1_oracle.py` declares thirteen literal
normative rows — nine receipt rows with per-effect-classification process-exit
and reconciliation policy, and four terminal rows. One test compares the
implementation matrices against that separate table; the exhaustive sweeps
derive every expected answer from the literal rows only. The sweeps examine
2 304 receipt flag combinations across nine states and four tools, 180 result
channel combinations, and eight terminal combinations, admitting 36, 52, and 4
respectively.

## 15. Final M1 boundary

This specification does not claim `VERIFIED_INTEGRATION` or
`VERIFIED_INSTALLED_PATH`. It records no provider-specific runtime behavior,
does not authorize effects, and does not begin Milestone 2.
