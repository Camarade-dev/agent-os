# Paired Runner ADR Register

This register records the twelve architecture decisions fixed by the governing
implementation plan. Every decision below is FROZEN_BY_GOVERNING_PLAN. A later
change requires a new ADR, an impact analysis for A/B fairness, and a
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
  identity, canonical arguments, scope, causal predecessor, timestamps,
  transport, prompt, model, and grammar identities.
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

## Register closure

The decisions above are the governing architecture boundary for the next
milestone. Any implementation that conflicts with one of them is not a
permitted continuation of this freeze.

## Milestone 1 evidence and clarifications

Milestone 1 adds the pure package `admissible.paired_runner` and the artifacts
`M1_EXECUTABLE_ARCHITECTURE_SPEC.md`, `M1_SCHEMA_CATALOG.json`,
`M1_ALLOWED_CONDITION_DIFFERENCES.json`, and `M1_VALIDATION_REPORT.json`.
The package is a fresh standard-library implementation; it imports none of
the historical runner, long-run, high-autonomy, Cursor, broker, witness, or
effect paths listed by the foundation freeze.

- ADR-001/004 are represented by common transport, proposal, and future
  effect-executor identities plus a single `ModeDecision` boundary. This is a
  pure equality invariant, not physical runtime integration.
- ADR-003/005/009 are represented by strict proposal, receipt, terminal,
  run, session, clock, causal, and budget records. Durable publication,
  restart, and observation remain later milestones.
- ADR-006 is clarified: run identity fields are instance bindings, not causal
  A/B inputs. They are explicitly named as `instance_binding_exceptions` in
  the allowlist so parity has no implicit ignored fields.
- ADR-010 is clarified: effect receipts cannot contain task acceptance;
  `TerminalManifest` records independent evaluator basis and keeps process
  completion separate from task acceptance.
- ADR-011/012 remain absolute exclusions. No V14–V18 object, production root,
  historical module, or Cursor `--force --trust` path is a fixture or import.

The M1 evidence closes only the statuses recorded for the 17 in-scope matrix
records. No ADR is reopened, weakened, or used to authorize Milestone 2.
