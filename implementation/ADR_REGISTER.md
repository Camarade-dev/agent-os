# Paired Runner ADR Register

This register records the twelve architecture decisions fixed by the governing
implementation plan, plus ADR-013 and ADR-014, which record the two bounded M1
repair boundaries, plus ADR-015 through ADR-017, which record the Milestone 2
platform, shared-executor, and durability boundaries. Every decision below is FROZEN_BY_GOVERNING_PLAN or
explicitly bounded by its status. A later change requires a new ADR, an impact analysis for A/B fairness, and a
requirement-matrix revision. No ADR is reopened or weakened by Milestone 0.

## ADR-001 — Un seul transport modèle

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: Conditions A and B use the same model executable,
  executable digest, transport, model, reasoning configuration, continuation
  rules, and tool-call reception. The Codex app-server canary is the reference
  transport; the Cursor --force --trust product path is not the target.
- Evidence supporting it: Governing plan section 2/ADR-001; fdb009a canary
  source and installed v6 archive contain app-server --stdio, while the
  selected product source contains a separate Cursor package-bin path.
  Installed v6 selected member bytes match the fdb009a canary source.
- Affected current components: admissible/capsule/codex_protocol.py,
  admissible/capsule/host_codex_backend.py,
  admissible/delegated_gate/native_executor.py, and the v6 zipapp.
- Forbidden alternatives: Cursor in one condition and Codex in the other;
  silent provider/model fallback; a second transport hidden behind a retry.
- Consequences: A/B causality can isolate governance only; the canary
  transport must be explicitly extracted or composed into the future package.
- Open validation work: M1 must define the transport interface and M3/M5 must
  prove identical transport identity in provider-free A and B.
- Milestone responsible for closure: M1 specification; M3 provider-free
  transport; M5 direct mode; M7 parity.

## ADR-002 — Une seule grammaire d’outils

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: Both conditions receive one canonical, structurally
  validated tool grammar. The initial set is list_files, read_file, write_file,
  and run_command.
- Evidence supporting it: fdb009a dynamic_tools_grammar() and the installed
  archive bind the four dynamic tools with bounded schemas and relative-path
  rules. The product Cursor path exposes native capabilities.
- Affected current components: fdb009a host_codex_backend.py,
  protocol_schemas/DynamicToolCall*.json, and product native_executor.py.
- Forbidden alternatives: native Cursor tools as a hidden second grammar; a
  condition-specific tool; unvalidated free-form shell/file calls.
- Consequences: Tool additions require a new requirement/ADR impact and must
  be identical in A and B.
- Open validation work: M1 round-trip and unknown-field tests; M2 effect
  implementation; M7 parity gate.
- Milestone responsible for closure: M1 and M2, with M7 parity.

## ADR-003 — Un bus canonique de propositions d’action

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: Every model tool request becomes a canonical proposal
  before any effect. The proposal carries run/condition/session/turn/proposal
  identity, one typed canonical tool request, scope, causal predecessor,
  timestamps, transport, prompt, model, and grammar identities.
- Evidence supporting it: The canary dynamic-tool request path and pre-effect
  effect ledger record authoritative attempts/outcomes. The audit finds that
  the modern product package-bin path lacks equivalent per-tool receipts.
- Affected current components: fdb009a host_codex_backend.py and
  canary_launch.py; product native_executor.py; historical runner modules.
- Forbidden alternatives: mutation before durable proposal publication;
  relying on model text; using the operator log as the proposal bus.
- Consequences: Observation is below the causal governance boundary and must
  be common to A and B.
- Open validation work: M1 canonical schemas; M2 durable reservation and
  publication; M5 direct-mode proof.
- Milestone responsible for closure: M1/M2/M5.

## ADR-004 — Un substrat partagé d’observation et d’effets

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: A and B share the physical observer, validator, effect
  launcher, process supervisor, output collector, mutation observer, receipt
  publisher, and run-state update. Only the decision interface differs.
- Evidence supporting it: The canary capsule backend and boundary launcher
  demonstrate a connected Codex/effect boundary. The audit explicitly says
  product and canary paths are separate and neither is a generic paired runner.
- Affected current components: capsule backend/brokers, boundary launcher,
  managed_process.py, and product native executor.
- Forbidden alternatives: two independent executors; a governed-only observer;
  post-mutation policy evaluation.
- Consequences: Shared substrate work precedes real model integration.
- Open validation work: M2 functional/durability/soak tests and M5 allow-all
  A/B comparison.
- Milestone responsible for closure: M2 and M5.

## ADR-005 — Observation commune, gouvernance additionnelle

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: Common evidence has the same schema in A and B. B may
  add policy, delegation, refusal, invariant, and authority receipts, but those
  additions cannot alter base observations.
- Evidence supporting it: The audit identifies asymmetric operator-log versus
  structured-canary evidence and missing common resource accounting.
- Affected current components: frontier_comparison_metrics.py, canary
  effect/evidence ledger, and product read model.
- Forbidden alternatives: different base schemas; treating B-only evidence as
  a substitute for common observation; inferring A metrics from prose.
- Consequences: A common terminal/reconciliation manifest is mandatory.
- Open validation work: M2 observation ledger; M3 resource metrics; M7
  comparative manifest.
- Milestone responsible for closure: M2/M3/M7.

## ADR-006 — Même environnement expérimental

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: A and B use physically distinct environments derived
  from one immutable snapshot with equal security policies, dependencies,
  toolchain, filesystem/process/output/time limits, caches, and Git policy.
- Evidence supporting it: README product assumptions are Windows-only; the
  canary is Linux/bubblewrap; the audit reports no common initial-state or
  environment manifest and shared-cache risk.
- Affected current components: product launcher preparation, canary
  confinement, source repository, and workspace setup.
- Forbidden alternatives: host-wide free execution for A; copied-but-
  unverified workspaces; shared mutable session/cache/authority roots.
- Consequences: Host choice and snapshot manifest are M1/M7 decisions, not
  inferred from V14.
- Open validation work: M1 constraints; M7 immutable snapshot and parity gate;
  M8 installed provider-free qualification.
- Milestone responsible for closure: M1/M7/M8.

## ADR-007 — Autorisation propriétaire d’une enveloppe

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: B uses a privileged owner broker and an exact envelope
  binding task, run, condition, prompt, state, model, executable, transport,
  grammar, policy, evaluator, workspace, scopes, budgets, expiration,
  cancellation, and terminal conditions.
- Evidence supporting it: The installed owner installation record, canary
  owner payload, root-generated record identity, signed receipt path, and V14
  physical consumer matrix are present. The audit also records that the modern
  product is not connected to this broker.
- Affected current components: canary owner_authority/*, production broker
  roots, and product in-process authorization digest.
- Forbidden alternatives: model-created authority; caller-supplied production
  identity; production broker as a test fixture; implicit phrase/digest
  authority.
- Consequences: Later authority tests require a disposable root; no production
  authority is part of implementation validation.
- Open validation work: M4 generic envelope, expiry/revocation, negative
  matrix, and broker crash tests.
- Milestone responsible for closure: M4.

## ADR-008 — Autorisation de délégation, pas micro-approbation humaine

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: After owner delegation, Admissible autonomously
  allows/refuses effects inside the envelope; out-of-envelope actions fail
  closed and all decisions are durable and explainable.
- Evidence supporting it: The canary pre-effect gate orders all identity,
  scope, budget, and authority checks before owner consumption/effects.
- Affected current components: canary pre-effect gate and effect ledger;
  product prompt/contract/post-run mediation.
- Forbidden alternatives: operator reconstruction of implicit authority;
  per-command human micro-approval; post-effect policy decisions.
- Consequences: Human intervention policy is an explicit metric and terminal
  input, not a hidden control path.
- Open validation work: M4 policy decision records and negative cases; M5
  direct mode must carry no Admissible decision.
- Milestone responsible for closure: M4/M5.

## ADR-009 — État durable multi-session

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: Run state is durable, explicit, monotone except
  permitted continuation transitions, restart/replay resistant, and supports
  the full lifecycle from CREATED through ARCHIVED.
- Evidence supporting it: The audit says both current production paths are
  one-shot; product active control state is in memory, while the canary is one
  thread/turn with no continuation across invocations.
- Affected current components: canary session_store/state, product
  launcher/recovery stores, and historical long-run modules.
- Forbidden alternatives: relaunching a new run as continuation; active state
  only in memory; automatic replay after an ambiguous effect.
- Consequences: Multi-session state must be newly specified and cannot be
  revived from historical modules without provenance.
- Open validation work: M1 state schemas; M3 checkpoint/restart/continuation
  tests; M4 authority-state integration.
- Milestone responsible for closure: M1/M3/M4.

## ADR-010 — Évaluateur commun et indépendant

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: A and B use the same evaluator after model stop. It
  checks physical workspace state and requirements, not model text, exit code,
  or model-selected tests alone.
- Evidence supporting it: The canary independently checks exact CANARY.txt/Git
  state; the product read model reconstructs evidence, but the audit finds no
  generic independent benchmark evaluator.
- Affected current components: canary finalizer/verification, product
  read-model, and admissible/evaluator.
- Forbidden alternatives: provider claim as acceptance; exit code as task
  success; separate evaluators for A and B; OBSERVED_ONLY as acceptance.
- Consequences: Evaluator specification precedes benchmark selection and must
  remain outside the causal governance difference.
- Open validation work: M6 generic evaluator fixtures and M7 paired
  comparative manifest.
- Milestone responsible for closure: M6/M7.

## ADR-011 — V14–V18 sont historiques et immuables

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: V14–V18 are evidence/reference only. They cannot be
  modified, rerun, reminted, newly authorized, copied under a new identity, or
  used as mutable future benchmark state.
- Evidence supporting it: V14 final-generation SHA-256
  854af52fc45531ee48d4dc0b086ac867456f4ba7d8d6f306746194cc3ceb9d31,
  BIND_STATE SHA-256
  674251343d455ddf463d3c1d61f150cc172baa135f04a0a92cc30f5b950c871e, and
  V18 terminal pointer SHA-256
  ae17566b2f8161434ec913fedb883a4c2b9c4bb660881ceb4455d05c1d0b7353 are
  physically present. The pointer says recovery success, no new mint, and no
  new Codex execution.
- Affected current components: V14–V18 evidence roots, installed canary,
  production witness/owner roots, and future benchmark planning.
- Forbidden alternatives: V14 preparation reuse; V18 recovery as benchmark
  preparation; version-number continuation; witness refresh.
- Consequences: A future run requires new identities and a new preparation only
  after later qualification.
- Open validation work: Preserve and re-hash historical anchors; do not
  execute historical scripts.
- Milestone responsible for closure: M0 freeze; enforced through M9.

## ADR-012 — Pas de reprise implicite des modules historiques

- Status: FROZEN_BY_GOVERNING_PLAN
- Governing decision: No historical multi-turn module is active merely because
  it exists. Reuse requires a named manifest entry, requirement link,
  inspection, tests, explicit integration, and build-manifest inclusion.
- Evidence supporting it: The selected repository contains long_run_*,
  high_autonomy_*, and historical_pairing_* modules; README says historical
  code is outside the judge-facing path. Their source digests are listed as
  excluded in SOURCE_OF_TRUTH.json.
- Affected current components: historical runners, high-autonomy modules,
  product historical-pairing adapters, and tests.
- Forbidden alternatives: importing a historical controller as a hidden
  runner; treating historical tests as future integration; inventing a V19 or
  continuing V14–V18 numbering.
- Consequences: Future extraction is an explicit migration with a new package
  namespace and provenance record.
- Open validation work: M1 import-closure review and M8 installed-path
  negative check for unexpected historical modules.
- Milestone responsible for closure: M0 freeze; revalidated in M1/M8.

## ADR-013 — Réparations bornées de la spécification M1

- Status: `M1_BOUNDED_REPAIR_BOUNDARY`
- Governing basis: the independent M1 closure findings M1-R01 through
  M1-R05 and the governing plan's M1 schema/round-trip requirements.
- Decision: keep all affected schema versions at `1` because M1 has no
  external or runtime persistence contract yet. Replace generic proposal
  arguments with four closed typed request/result pairs; bind proposals and
  reservations to the exact experiment specification; enforce exhaustive
  receipt and terminal matrices; and require typed terminal manifests for
  comparative closure.
- Validation boundary: pure standard-library construction, exact-key
  deserialization, canonical fingerprints, table-driven state tests, and
  typed comparative reconciliation only. No effect, policy, broker,
  authority, transport, evaluator execution, installation, or provider path
  is introduced.
- Consequences: the schema catalog grows from 19 to 27 descriptors; the
  version-1 catalog is regenerated canonically; old generic M1 fixture shapes
  are intentionally refused. A future runtime persistence implementation must
  adopt these exact definitions or issue a new versioned ADR before use.
- Forbidden alternatives: accepting arbitrary tool dictionaries, relying on
  caller-side specification comparisons, treating timeout/ambiguity as
  completion, accepting unreconciled terminals, or presenting terminal
  fingerprints without typed reconciliation.
- Requirements affected: ARCH-02, ARCH-04, ARCH-05, EXEC-01 through EXEC-05,
  BASE-01, BASE-02, and FAIR-01 through FAIR-07. No out-of-scope requirement
  record is changed.

## ADR-014 — Deuxièmes réparations bornées de la spécification M1

- Status: `M1_SECOND_BOUNDED_REPAIR_BOUNDARY`
- Governing basis: the independent M1 closure findings M1-R06 through
  M1-R11, reproduced against commit
  `41942a3ed3a85d4f47b38a29b9d86368523555cd` before any repair.
- Decision: keep all affected schema versions at `1` because M1 still has no
  runtime or external persistence contract, and record explicitly that no
  pre-repair M1 object is accepted as authoritative. Introduce a typed
  `ToolGrammarSpecification` and `ToolGrammarEntry` so the experiment's tool
  grammar is machine-verifiable rather than an opaque label; bind the exact
  typed `EvaluatorSpecification` into `ExperimentSpecification` and require
  every terminal to be issued by it; add typed fail-closed reconciliation for
  reservations (`validate_for_decision`) and receipts
  (`validate_for_causal_chain`); make the receipt contract effect-aware so
  process-exit data exists only for `run_command`; and require every tool
  result to validate against its exact request.
- Validation boundary: pure standard-library construction, exact-key
  deserialization, canonical fingerprints, independently declared normative
  state tables, and typed causal reconciliation only. No effect, process,
  policy, broker, authority, transport, evaluator execution, installation, or
  provider path is introduced.
- Consequences: the schema catalog grows from 27 to 29 descriptors; the
  version-1 catalog is regenerated canonically; every pre-repair
  specification, receipt, run-command result, and self-declared grammar
  fingerprint is refused. Structural validation and authoritative typed
  reconciliation are now documented as different guarantees, and a restored
  reservation or receipt is not authoritative until the typed reconciliation
  succeeds.
- Forbidden alternatives: comparing unrelated fingerprint domains to claim an
  evaluator binding; treating a label `IdentityReference` as proof of grammar
  contents; requiring or accepting a process exit code for a non-process
  tool; accepting a tool result that does not answer its exact request;
  accepting an argv whose executable token is empty; deriving an exhaustive
  state-matrix test's expected answers from the matrix under test.
- Requirements affected: ARCH-02, ARCH-04, ARCH-05, EXEC-01 through EXEC-05,
  BASE-01, BASE-02, and FAIR-01 through FAIR-07. EXEC-02 and EXEC-05 are
  restored to `DESIGNED` because their whole requirements depend on durable
  pre-effect publication and on an effect executor that does not yet exist.
  No out-of-scope requirement record is changed.

## ADR-015 — Plateforme et durabilité de qualification initiale du Milestone 2

- Status: `M2_PLATFORM_CONTRACT_SELECTED`
- Governing basis: the governing plan's Milestone 2 requirements and the
  Milestone 0 record that no physical host had yet been selected. Milestone 2 is
  the first platform-dependent runtime milestone, so the platform is decided
  before any runtime code is trusted.
- Decision: the initial M2 qualification platform is **Linux POSIX process,
  signal, and filesystem semantics with the CPython standard library only**.
  The current development/qualification host may be WSL2, and it was
  (Linux 6.18.33.2-microsoft-standard-WSL2, CPython 3.12.3). **WSL2 success is
  explicitly not clean-host Linux qualification.** There is no Windows Cursor
  path, no Node dependency, no provider dependency, and no production authority
  dependency. This is the default expected decision of the assignment; no
  alternative platform was chosen.
- Consequences: the substrate may rely on POSIX sessions and process groups,
  `killpg`, `O_NOFOLLOW`/`O_DIRECTORY` descriptor-relative opens, `fsync`,
  `os.link` no-replace commits, and `selectors`. It may not rely on Windows,
  macOS, Node.js, npm, a network filesystem, or an installed production root.
  Every M2 measurement is a WSL2 measurement and is labelled as such.
- Durability boundary: `publish` claims only that the file contents and the
  parent directory entry were handed to `fsync` and that the committed bytes
  were read back and compared. It claims nothing about device write caches,
  virtualised block devices, or power loss. The thirteen fault-injection points
  are deterministic in-process simulations, not power cuts.
- Measurement boundary: child CPU time and peak RSS come from
  `getrusage(RUSAGE_CHILDREN)` deltas, which aggregate every reaped child of the
  controller, so they are recorded as `OBSERVED_BEST_EFFORT` upper bounds. An
  unavailable metric is recorded with an explicit availability value and a
  `None` measurement; it is never recorded as zero. No token or model cost
  metric exists in M2.
- Controller-memory threshold, declared before the heavy soak was run:
  analytic retention bound `2 * max_output_bytes + 262144` bytes, and measured
  controller RSS growth no greater than 64 MiB above the pre-soak baseline for
  the 1 GiB / 1 000 000-line workload.
- Forbidden alternatives: implementing platform-specific behaviour without this
  ADR; combining the Windows Cursor product assumptions with the Linux Codex
  canary assumptions; claiming clean-host, installed-path, or power-loss
  durability from WSL2 evidence; recording an unavailable metric as zero.
- Full contract: `implementation/M2_PLATFORM_AND_DURABILITY_CONTRACT.md`.
- Requirements affected: EXEC-02, EXEC-05, EXEC-06, EVID-01 through EVID-08,
  LONG-07, LONG-08, TEST-03, TEST-08. No out-of-scope requirement record is
  changed.

## ADR-016 — Un seul exécuteur d'effets physique partagé

- Status: `M2_SHARED_EFFECT_SUBSTRATE_BOUNDARY`
- Governing basis: ADR-004 and ADR-005, which require A and B to share the
  physical observer, validator, effect launcher, process supervisor, output
  collector, mutation observer, receipt publisher, and run-state update.
- Decision: `admissible.paired_runner.effects.SharedEffectSubstrate.execute` is
  the single physical execution entry point for both future conditions. It takes
  typed M1 objects — `ExperimentSpecification`, `CanonicalProposal`,
  `ModeDecision`, `EffectReservation` — and never a mode-specific command path.
  `decision.permits_effect` is the only place the decision is consulted; after
  that point no code inspects the condition, the decision value, or any
  governance field. The executor is not duplicated.
- Enforcement: the substrate refuses `REFUSE`, `TERMINATE_RUN`, and
  `REQUIRE_CONTINUATION` before any reservation or effect exists, and physically
  enforces validate → publish proposal → validate decision → reserve → publish
  STARTED → effect. The effect boundary is instrumented, and the tests read the
  filesystem at that instant rather than memory.
- Evidence: a `sys.settrace` capture proves the set of executed
  `(function, line)` pairs after the decision boundary is identical for a DIRECT
  `DIRECT_EXECUTION` fixture and a GOVERNED `ALLOW` fixture.
- Boundary: M2 contains **no policy engine**. `ModeDecision` is an input the
  substrate obeys and reconciles; nothing in M2 decides whether a proposal
  should be allowed, and no M2 test claims that a policy engine exists. Owner
  authorization, the broker, and the policy gate remain Milestone 4.
- Forbidden alternatives: a second executor for the baseline; a governed-only
  observer; any post-mutation decision; a mode-specific effect implementation;
  an automatic replay of an ambiguous effect.
- Requirements affected: as ADR-015.

## ADR-017 — Publication durable sans remplacement et rapprochement fail-closed

- Status: `M2_DURABILITY_BOUNDARY`
- Governing basis: ADR-003 (no mutation before durable proposal publication) and
  ADR-009 (durable, replay-resistant state).
- Decision: one primitive publishes every immutable object, committing with
  `os.link()` so an existing name is never replaced. Re-publishing byte-identical
  canonical content is `DUPLICATE_IDENTICAL` and succeeds; different content for
  the same identity is `CONFLICT_DIFFERENT` and fails closed. Temporary files
  carry a reserved prefix, are reported explicitly, and are never counted as
  committed objects. A committed object that is not canonical is `CORRUPT` and
  fails closed.
- Recovery decision: recovery reconstructs only from durable bytes. Once a
  `STARTED` record is durable the effect may have occurred, so a fresh
  controller raises `AmbiguousEffectRefused` and never replays. `replay_permitted`
  is false in every reconciliation classification. A mutating ambiguity is
  classified separately from a read-only ambiguity.
- Boundary: M2 implements deterministic single-effect recovery only. Full
  multi-session restart, checkpoints, and cumulative budgets remain Milestone 3.
- Forbidden alternatives: overwriting a different object under the same
  identity; treating a temporary file as committed; interpreting a corrupt
  object; any automatic retry after a potentially consumed effect.
- Requirements affected: as ADR-015.

## Register closure

The decisions above are the governing architecture boundary for the next
milestone. Any implementation that conflicts with one of them is not a
permitted continuation of this freeze. ADR-013 and ADR-014 close only the two
bounded M1 repair boundaries and did not authorize Milestone 2. ADR-015 through
ADR-017 close only the Milestone 2 shared-substrate boundary and do **not**
authorize Milestone 3, a model transport, a policy engine, an owner authority,
or any provider contact.

## Milestone 1 evidence and clarifications

Milestone 1 adds the pure package `admissible.paired_runner` and the artifacts
`M1_EXECUTABLE_ARCHITECTURE_SPEC.md`, `M1_SCHEMA_CATALOG.json`,
`M1_ALLOWED_CONDITION_DIFFERENCES.json`, `M1_VALIDATION_REPORT.json`,
`M1_BOUNDED_REPAIR_REPORT.json`, and
`M1_SECOND_BOUNDED_REPAIR_REPORT.json`.
The package is a fresh standard-library implementation; it imports none of
the historical runner, long-run, high-autonomy, Cursor, broker, witness, or
effect paths listed by the foundation freeze.

- ADR-001/004 are represented by common transport, proposal, and future
  effect-executor identities plus a single `ModeDecision` boundary. This is a
  pure equality invariant, not physical runtime integration. The proposal
  now carries a typed tool request and the reservation derives the executor
  from the exact specification.
- ADR-003/005/009 are represented by strict proposal, typed tool request and
  result, receipt-state, terminal-state, run, session, clock, causal, and
  budget records. Durable publication, restart, and observation remain later
  milestones.
- ADR-006 is clarified: run identity fields are instance bindings, not causal
  A/B inputs. They are explicitly named as `instance_binding_exceptions` in
  the allowlist so parity has no implicit ignored fields.
- ADR-010 is clarified: effect receipts cannot contain task acceptance;
  `TerminalManifest` records independent evaluator basis and keeps process
  completion separate from task acceptance. Comparative closure requires the
  typed DIRECT and GOVERNED terminal objects and a separate typed
  reconciliation path after deserialization.
- ADR-011/012 remain absolute exclusions. No V14–V18 object, production root,
  historical module, or Cursor `--force --trust` path is a fixture or import.
- ADR-002 is strengthened by ADR-014: the grammar is a typed manifest binding
  the four tool names, exact request/result schema IDs and versions, effect
  classifications, and descriptor fingerprints, and a proposal must prove
  membership in that exact grammar.
- ADR-010 is strengthened by ADR-014: the experiment binds one exact
  `EvaluatorSpecification` whose environment equals the experiment
  environment, and a terminal issued by any other evaluator is refused in both
  runs of a comparative closure.
- ADR-003/004 are strengthened by ADR-014: structural validation is explicitly
  non-authoritative, and reservations and receipts require typed causal
  reconciliation before they may be treated as authoritative for execution.

The M1 evidence closes only the statuses recorded for the 17 in-scope matrix
records. EXEC-02 and EXEC-05 are restored to `DESIGNED` by ADR-014 rather than
being carried at a status their whole requirements do not support. No ADR is
reopened, weakened, or used to authorize Milestone 2.

---

## ADR-M2R-01 — One bubblewrap capsule is the effect boundary

**Status:** Accepted (Milestone 2 critical repairs)

**Context.** The Milestone 2 `run_command` path restricted only the working
directory. A typed command could name any absolute host path, reach the
network, read the operator's home directory, and rewrite the durable evidence
store that was supposed to be the independent record of what it did.

**Decision.** Every command executes inside one `bubblewrap` capsule, shared
identically by the future DIRECT and GOVERNED modes. The workspace is exposed at
the single internal path `/workspace`; only an explicit read-only toolchain list
is exposed; `/tmp` and `/proc` are private; the network namespace is unshared;
`--clearenv` removes every inherited credential and the host `HOME`; and the
durable evidence root is absent from the mount namespace entirely.

**Consequences.** The boundary is enforced by the kernel, not by the command's
cooperation. A refusal is `ENOENT` — the path does not exist — rather than a
permission decision. If the mechanism is unavailable, readiness refuses before
any proposal is published; there is no unsandboxed fallback. Contract:
`implementation/M2_SANDBOX_CONTRACT.md`.

**Rejected alternative.** An in-process restriction (path validation, `chroot`
without namespaces, or an allowlist checked by the controller) was rejected
because it depends on the effect process not routing around it.

## ADR-M2R-02 — Quiescence is derived from `ECHILD`, not from pipe EOF

**Status:** Accepted (Milestone 2 critical repairs)

**Context.** Supervision ended when both pipes reached EOF. A descendant with
redirected output could survive a `COMPLETED` receipt and mutate the workspace
afterwards, and a direct child that closed its pipes but kept running was killed
after a fixed two-second grace regardless of its own requested timeout.

**Decision.** The capsule runs a private PID namespace whose init
(`_capsule_init.py`, PID 1 via `--as-pid-1`) reaps every descendant and derives
quiescence from `ECHILD`. The controller loop ends only when the launcher is
reaped, which happens only after that observation.

**Consequences.** `descendants_reaped` is a kernel observation rather than an
assertion, and `ProcessObservation` validation forbids claiming it independently
of the observed quiescence. A surviving descendant or a missing process-domain
observation can never produce `COMPLETED`. `setsid` and double-fork cannot
evade termination, because the namespace — not the process group — is the
boundary.

## ADR-M2R-03 — A ledger entry may never certify its own reconciliation

**Status:** Accepted (Milestone 2 critical repairs)

**Context.** The ledger entry was written with
`final_reconciliation_state="RECONCILED_COMPLETE"` *before* reconciliation ran,
and `RunEffectLedger.verify` re-read only the entry's own bytes — succeeding
even when every object the entry referenced had been deleted.

**Decision.** `EffectLedgerEntry` is type-constrained to
`PENDING_VERIFICATION` and cannot be constructed claiming success. A separate
`FinalReconciliation` record, published only after verification, binds the exact
pending entry and the fingerprint of every verified object. `verify` now
verifies the entire typed chain.

**Consequences.** The claim and the verdict are different records, so the
circularity is gone. Reconciliation requires the exact experiment specification
or an externally supplied exact fingerprint, so the chain cannot certify itself.
Specification: `implementation/M2_TYPED_RECONCILIATION_SPEC.md`.

## ADR-M2R-04 — Git observation runs no repository-controlled code

**Status:** Superseded by ADR-M2S-02 (Milestone 2 second critical repairs)

**Context.** `WorkspaceBinding.bind` ran a Git observation before any proposal
was durable, and the observer honoured repository-local `core.fsmonitor` — so a
hostile repository could execute a program with no proposal, no decision, and no
evidence.

**Decision.** Binding executes nothing; it is pure syscalls. Git observation
happens only after the proposal is durable, runs inside the shared capsule, and
overrides every setting through which Git can run a program on the command line,
where a configuration file cannot outrank it.

**Consequences.** Two independent mechanisms guard the same defect, because
either alone would be a single point of failure. The observation takes no
optional lock and mutates neither the index nor the worktree.

## ADR-M2R-05 — Physical refusal is resolved before `STARTED` exists

**Status:** Accepted (Milestone 2 critical repairs)

**Context.** A missing or symlinked target produced a durable `STARTED` record,
a crossed boundary, and `ledger boundary=true`, alongside a `REFUSED` receipt
with `effect_started=false` — evidence that contradicted itself.

**Decision.** `prepare_effect` resolves every physical precondition and retains
the proven descriptors before `STARTED` is published; the tools then act on
those descriptors rather than re-resolving a path string.

**Consequences.** A refusal is genuinely pre-effect and every record agrees.
Retaining the descriptors also closes the race between the check and the use.
Directory creation for `create_parents` is deliberately excluded from
preparation, because creating a directory is itself a mutation.

## ADR-M2T-01 — Effects run on a private view; trusted export mutates the source

**Status:** Accepted (Milestone 2 third critical repairs), supersedes the
shared-workspace half of ADR-M2S-01

**Context.** ADR-M2S-01 closed endpoint *creation* inside the capsule and refused
pre-existing specials at admission. A live writable bind of the authorized
workspace still allowed a host to create a FIFO after admission; `open` of that
FIFO is not distinguishable from `open` of a regular file under seccomp.

**Decision.** Materialise a private per-effect copy before `STARTED`, bind it by
descriptor, run the effect only against that view, and after quiescence export
only a closed regular-file/directory/symlink change set. Source mutation or
unsupported private inodes refuse export. Seccomp remains defence in depth.

**Consequences.** The second-repair "known limitation" about mid-execution host
FIFOs is withdrawn as an accepted limitation — it was the defect. Export is a
new trusted surface with an explicit grammar and crash-classifiable partial
states.

## ADR-M2T-02 — Runtime inputs are descriptor-bound; cgroup membership is verified before exec

**Status:** Accepted (Milestone 2 third critical repairs), extends ADR-M2S-05

**Context.** Pathname recheck then pathname `Popen` left a replacement window.
Cgroup `attach()` return values were ignored and mechanism was derived from
directory existence.

**Decision.** Open and verify launcher/interpreter/init/private-view descriptors
at the effect boundary; execute/mount through `/proc/self/fd/N` and
`--ro-bind-fd`/`--bind-fd`. Create the launcher stopped, attach, verify
`cgroup.procs` membership, then release; attachment failure refuses before
command execution; promised cgroup enforcement never silently degrades.

**Consequences.** Evidence binds the inode that actually ran. Aggregate cgroup
claims require verified membership. RLIMIT remains mandatory defence in depth.

## ADR-M2S-01 — Filesystem IPC is closed at the syscall, not by the network namespace

**Status:** Partially superseded by ADR-M2T-01 (Milestone 2 third critical repairs).
The seccomp half remains accepted; the shared live-workspace half does not.

**Context.** The sandbox contract stated that an unshared network namespace plus
an absent evidence path left no host capability reachable. That statement is
false. A pathname `AF_UNIX` socket is a filesystem object: it crosses an unshared
network namespace, and `SCM_RIGHTS` over it transfers an open descriptor for any
file the peer can open, including one absent from the capsule's mount namespace.
A FIFO in the writable workspace is the same bridge. The independent audit
reproduced both.

**Decision.** Two independent kernel-enforced mechanisms. A seccomp-BPF program,
assembled in-tree and loaded by `bwrap --seccomp` immediately before `execv`,
denies `socket(AF_UNIX)`, `socketpair(AF_UNIX)`, `mknod`, and `mknodat`; a
mismatched `seccomp_data.arch`, and on x86-64 any x32 syscall number, kills the
process, and an architecture with no recorded numbering is a readiness refusal.
Independently, no capsuled process starts over a workspace containing a socket,
FIFO, or device node, and that refusal happens before the durable `STARTED`
record exists.

**Consequences.** `SCM_RIGHTS` needs no rule of its own, because it travels only
over an `AF_UNIX` socket and none can be created or inherited. A command needing
local socket IPC or a FIFO now fails with `EPERM`; that is the documented
contract of the capsule. The second repair rejected private materialisation; the
third repair reinstates it (without requiring overlayfs) because admission plus
seccomp cannot close a host-injected FIFO on a live writable bind. See ADR-M2T-01.

## ADR-M2S-02 — The Git observer executes nothing, and fails closed instead

**Status:** Accepted (Milestone 2 second critical repairs), supersedes ADR-M2R-04

**Context.** ADR-M2R-04 neutralised every *known* setting through which Git runs
a program. That is a denylist, and the audit showed it is unclosable: a
repository names an arbitrary filter driver through `.gitattributes` and defines
it in its own configuration, and `git status` must run that driver to decide
whether a working-tree file matches the index. The shipped override list still
executed a repository-chosen program, after the durable `STARTED` record, during
what the evidence called an observation.

**Decision.** No `git` process. The observer parses `HEAD` and refs including
`packed-refs`, the binary index with its trailing SHA-1 verified, and objects
from loose storage and packfiles with delta resolution, and hashes working-tree
files into Git blob identities directly. Where the answer would require running a
program — any declared content conversion — the observation records
`GIT_CONVERSION_REQUIRED` and determines nothing further. The
`GIT_COMMAND_FAILED`, `GIT_EXECUTABLE_UNAVAILABLE`, and `GIT_SANDBOX_UNAVAILABLE`
availabilities were removed from the schema.

**Consequences.** There is no fallback to executing `git` anywhere in the module,
so the schema itself testifies that no command is run. The cost is that some
repositories are observed as explicitly undetermined rather than compared, and
that untracked counting does not evaluate ignore rules — both recorded in the
observation rather than silently approximated.

## ADR-M2S-03 — The run index is an event chain with one replaceable committed head

**Status:** Accepted (Milestone 2 second critical repairs)

**Context.** A one-summary-per-proposal index that discovers its extent by
counting until a name is absent cannot see past a gap, cannot distinguish a
truncated run from a shorter one, and cannot represent a crash between the
proposal and its outcome at all. All three were demonstrated.

**Decision.** One immutable hash-chained event per transition, with the proposal
event durable before any effect is possible; reconstruction scans every durable
name belonging to the run; and one `run-index-anchor` — the single replaceable
object in an otherwise no-replace store — records the committed head, advanced by
atomic rename only after the event it commits is durable.

**Consequences.** Gaps, surplus positions, reordering, duplication, foreign
records, a missing tail, and an anchor that outruns or lags its chain all fail
closed. The window between an event's commit and the head update is the named
`HEAD_UPDATE_PENDING` state, recovered by advancing the head onto an
already-durable, already-chained event. Rollback — deleting the newest event and
rewinding the head together — remains undetectable locally and is stated as
requiring an external anti-rollback anchor that Milestone 2 does not implement.

## ADR-M2S-04 — Run history is derived from durable bytes, never supplied

**Status:** Accepted (Milestone 2 second critical repairs)

**Context.** `RunEffectLedger.verify` took the proposal identities to verify from
its caller, so a restarted process could hand in an empty tuple and receive a
ledger that verified perfectly while omitting every effect already performed.

**Decision.** The ordered proposal set comes from the durable run index, which is
chain-verified against its committed head first. Refusals are verified by the
checked *absence* of a ledger entry, surplus entries fail closed, and the
substrate rebuilds its in-memory ledger from that derived history before
publishing any new proposal.

**Consequences.** History is no longer a parameter. The one remaining dial,
`require_closed`, decides only what happens to a proposal a crash left open — it
is what lets a restarted controller inspect a run in order to *refuse* replaying
it — and every closed proposal is verified equally strictly either way.

## ADR-M2S-05 — A capsule is identified by its bytes, and bounded by the kernel

**Status:** Accepted (Milestone 2 second critical repairs)

**Context.** The capsule descriptor bound a mechanism *name* and a resolved path,
so a replaced launcher, a substituted interpreter, an edited init, or a shadowing
`PATH` entry produced identical evidence for a different boundary. Separately, the
capsule applied no CPU, memory, process, descriptor, or file-size limit: a PID
namespace is a naming boundary, not a quota.

**Decision.** A typed `CapsuleRuntimeManifest` binds the launcher, interpreter,
in-capsule init, seccomp program, package source identity, declared toolchain
roots, and the namespace, mount, and containment contract, and is rechecked
before the proposal that authorises an effect is published. Per-command bounds
are applied by the init in the forked child immediately before `execv`, with a
per-effect cgroup v2 subtree added where the host delegates one, and the child
reads the limits back with `getrlimit` so the observation records enforcement
rather than intent.

**Consequences.** Readiness refuses rather than degrading: a filter the kernel did
not load, or a bound it did not honour, stops the run before any proposal. On a
host that delegates no cgroup subtree the recorded mechanism is `RLIMIT` and the
absence of aggregate accounting is stated in every resource observation.
