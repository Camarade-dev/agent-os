# Admissible Rigor Transfer Audit v0

**Date:** 2026-07-08  
**Repo:** `agent-os` (historical name)  
**Scope:** Historical Agent OS rigor vs current Admissible action-admission layer  
**Related:** [`admissible-agent-os-lineage.md`](admissible-agent-os-lineage.md), [`admissible-agent-os-boundary-audit.md`](admissible-agent-os-boundary-audit.md)

Machine-readable matrix: [`admissible-rigor-transfer-matrix.json`](admissible-rigor-transfer-matrix.json)

---

## Pre-audit diagnostics

| Flag | Result | Evidence |
|------|--------|----------|
| `RIGOR_AUDIT_IMPORT_BOUNDARY_CLEAN` | **YES** | Zero AST `agent_os` imports in `admissible/` (15 modules) and `benchmark/` (2 modules); `tests/test_admissible_boundary.py` |
| `RIGOR_AUDIT_AGENT_OS_HAS_LONG_RUN_PRIMITIVES` | **YES** | Full orchestrator pipeline (goal intake → requirements promotion), planning workspace CLI, fail-closed run closure, ~24.5k lines in `tests/test_agent_os.py` |
| `RIGOR_AUDIT_ADMISSIBLE_HAS_REFORMALIZED_CORE` | **YES (partial)** | Strong reformalization at execution boundary (envelopes, labels, evaluator, schemas, scoring, traces); long-run upstream governance not reformalized |
| `RIGOR_AUDIT_POSSIBLE_LONG_RUN_GAPS` | **YES** | Fixture-backed terminal/long-run demos; no live Cursor/Composer integration; no goal→plan→admit chain |
| `RIGOR_AUDIT_SHOULD_NOT_PORT_RUNTIME_AGENT_OS` | **YES** | Porting orchestrator/planning runtime would collapse Admissible back into a full governance orchestrator |
| `RIGOR_AUDIT_TOO_BROAD` | **NO** | This slice is audit/report only; no runtime semantics changed |

---

## 1. Executive Summary

### Direct answer

**Agent OS rigor was not accidentally bypassed; it was split across layers with uneven transfer.**

- **Reformalized strongly in Admissible:** execution-boundary action admission — capability vs authority, evidence sufficiency at the moment of side effect, policy/risk/reversibility/blast-radius in the action envelope, five canonical admission labels with precedence, auditable decision output, benchmark schemas, gold labels, deterministic scoring, run traces, claim boundaries, and dry-run discipline for demos.
- **Intentionally not transferred at runtime:** Agent OS upstream long-run governance — goal intake, source-bounded requirements extraction, draft/approved requirements promotion, planning workspace lifecycle, owner decision gates for artifact promotion, structured planning slices, fail-closed run closure, and workspace layout under `.agent-os/`.
- **Conceptually transferred but weakly implemented in Admissible:** source-bounded evidence discipline, human responsibility, approval scope, safe alternatives, and traceability across a multi-hour agent session — present in specs and partial truth-trace fields, but not enforced with Agent OS–grade fail-closed gates.
- **Lost and important for Cursor Composer 2.5 Slither-like long-run demos:** a credible bridge from frontier agent output → action envelope construction → admission → (optional) execution logging across a real multi-step session, plus upstream mission/scope discipline so the agent does not drift into unrelated side effects.

### Overall classification

| Dimension | Verdict |
|-----------|---------|
| Execution-boundary admission rigor | **Reformalized strong** — Admissible exceeds Agent OS here |
| Upstream planning/governance rigor | **Not transferred** — remains in `agent_os/` lineage |
| Long-run demo credibility (Cursor/Composer) | **Weaker than Agent OS for end-to-end** — by design scope, not by accident |
| Independence from `agent_os` | **Clean** — discipline reused conceptually, not at import/runtime |
| Risk of Admissible becoming full orchestrator | **Low today**; **high** if orchestrator/planning runtime is ported wholesale |

**Bottom line:** Admissible is a **correctly scoped sibling** that **reformalized the execution-boundary slice** of Agent OS doctrine. It did **not** rebuild a weaker copy of the full Agent OS long-run governance stack — it **left that stack behind** in `agent_os/`. For a Cursor Composer 2.5 Slither-like demo, the gap is not “Admissible forgot admission rules”; it is “nothing in-repo composes frontier agent loops + Agent OS planning gates + Admissible admission into one thesis-aligned long-run harness.”

---

## 2. Method

### Inspection approach

1. **Package inventory** — `agent_os/` (6 modules + templates), `admissible/` (15 modules), `benchmark/` (schemas, cases, scoring).
2. **Documentation review** — `docs/thesis.md`, `docs/why-agent-os.md`, `docs/primitives.md`, planning/orchestrator docs, Admissible thesis/envelope/benchmark specs, lineage and boundary audits, Slither-like demo contract.
3. **AST import boundary check** — same method as `tests/test_admissible_boundary.py`; ripgrep corroboration.
4. **Test review** — `tests/test_agent_os.py` (orchestrator slices CORE_ORCHESTRATOR_001–025, planning lifecycle, run closure); 24 `tests/test_admissible_*.py` files (decision, evaluator, scoring, runners, boundary, demos).
5. **Demo artifact review** — Terminal Agent Dry-Run v0, Long-Run Truth Console v0, Gemini live demo traces, `benchmark/reports/*`.
6. **Example fixture review** — `examples/planning-workspace-slither-like/`.
7. **Primitive-by-primitive mapping** — each Agent OS rigor primitive classified against Admissible equivalent, reuse type, rigor status, long-run relevance, thesis alignment, and recommendation.

### What this audit did not do

- No runtime benchmark performance claims.
- No deletion or migration of `agent_os/`.
- No modification of Admissible evaluator semantics.
- No empirical Cursor/Composer session capture.

---

## 3. System Boundary Recap

| System | Role | Runtime in repo |
|--------|------|-----------------|
| **Agent OS** | Historical governed-delegation substrate: mission/authority/evidence/audit/owner-decision/closure under `.agent-os/`; orchestrator goal→requirements pipeline; planning workspaces | `agent_os` CLI; no Admissible imports |
| **Admissible** | Active benchmarkable action-admission layer before side effects | `admissible` + `benchmark` packages; **must not** import `agent_os` |

Shared vocabulary (evidence, audit, admissible, owner decision) refers to **different artifacts** with different schemas. See lineage doc §3–§7.

---

## 4. High-Level Comparison

### Agent OS — orchestration/governance system

Agent OS is a **local epistemic protocol** (`docs/thesis.md`): seven run primitives, fail-closed closure, planning workspaces, and a **gate-heavy orchestrator** that moves artifacts from raw goal → intake → clarifications → owner readiness → draft requirements → validation → approval → planning transport — each step producing append-only JSON with explicit `non_authority` flags.

Strength: **long-horizon governance** — what was asked, what was permitted, what was promoted, what was verified, what the owner accepted, how the run ends.

Weakness relative to Admissible thesis: **no execution-boundary admission object model**, no benchmark harness, no standardized pre-side-effect decision labels for tool calls.

### Admissible — action-admission/benchmark system

Admissible is an **execution-boundary evaluator** (`docs/Admissible_THESIS.md`): the model proposes; Admissible decides what **may** execute. Unit of evaluation is the **action envelope**; output is one of five **admission decisions** with audit trace and optional safer next step.

Strength: **benchmarkable, schema-backed, provider-agnostic** admission with deterministic rules-only reference evaluator, frontier baselines (mock/HF/Gemini), scoring metrics (false-allow, missing-escalation, etc.), and explicit claim boundaries.

Weakness relative to Agent OS long-run demos: **no upstream goal/plan/closure lifecycle**; terminal and long-run demos are **fixture-backed**, not live Cursor/Composer captures.

---

## 5. Rigor Transfer Matrix

See full machine-readable entries in [`admissible-rigor-transfer-matrix.json`](admissible-rigor-transfer-matrix.json). Summary table:

| Agent OS primitive | Original purpose | Agent OS artifact(s) | Admissible equivalent | Reuse type | Rigor status | Long-run relevance | Thesis alignment | Gap | Recommendation |
|--------------------|------------------|----------------------|------------------------|------------|--------------|-------------------|------------------|-----|----------------|
| Goal intake | Durable record of raw goal + ambiguity/readiness; no planning authority | `agent_os/orchestrator.py`, `goal-intake.json`, `docs/orchestrator/goal-intake-artifact.md` | `user_request` block in envelope; `LONG_RUN_PROMPT` in truth trace | `INTENTIONALLY_OUT_OF_SCOPE` | `MISSING_ACCEPTABLE` | HIGH | ALIGNED | No intake state machine in Admissible | `KEEP_AS_LINEAGE`; `DOCUMENT_ONLY` cross-layer contract |
| Source-bounded requirement extraction | Requirements only from explicit transported source | `draft_requirements_from_source`, transport artifacts | Envelope `evidence.available` / `missing`; rules_only checks | `CONCEPTUAL_TRANSFER` | `WEAKER_IN_ADMISSIBLE` | MEDIUM | ALIGNED | No extraction pipeline or SOURCE_BOUNDED provenance flag | `PORT_AS_ADMISSIBLE_CONCEPT` in envelope provenance fields |
| Draft requirements | `DRAFT-REQ-*` never promoted without gate | `local-agentic-spec.md`, orchestrator draft validators | N/A (planning artifact) | `INTENTIONALLY_OUT_OF_SCOPE` | `NOT_APPLICABLE` | MEDIUM | ALIGNED | Out of admission-layer scope | `KEEP_AS_LINEAGE` |
| Approved requirements | `REQ-*` only after owner approval gate | `approved-requirements.json`, promotion functions | N/A | `INTENTIONALLY_OUT_OF_SCOPE` | `NOT_APPLICABLE` | MEDIUM | ALIGNED | — | `KEEP_AS_LINEAGE` |
| Owner decision gates (orchestrator/planning) | Owner authorizes next stage; record ≠ execution | `OWNER_READINESS_DECISION`, `PLANNING_OWNER_DECISION`, `AUTHORIZE_*` constants | `REQUIRE_HUMAN_APPROVAL` label; `authority_context` in envelope | `REFORMALIZED_WEAK` | `WEAKER_IN_ADMISSIBLE` | HIGH | PARTIALLY_ALIGNED | Agent OS: multi-stage artifact gates; Admissible: per-action gate only | `DOCUMENT_ONLY` vocabulary map in lineage (exists); `ADD_LONG_RUN_DEMO_REQUIREMENT` for per-action approval trace |
| Promotion / admissibility gates | Structural readiness for owner review / promotion | Orchestrator preflights, `requirements_*_preflight` | Admission label precedence (`resolve_precedence`) | `CONCEPTUAL_TRANSFER` | `EQUIVALENT` (different domain) | MEDIUM | ALIGNED | Homonym “admissible” documented | `DOCUMENT_ONLY` (done) |
| Planning slices | Ordered work breakdown for long runs | `implementation-plan.md`, `PLANNING_RUN_SLICE` JSON | N/A | `INTENTIONALLY_OUT_OF_SCOPE` | `MISSING_ACCEPTABLE` | HIGH | ALIGNED | Slices are orchestration, not admission | `KEEP_AS_LINEAGE`; long-run demo may reference slices externally |
| Structured planning slice format | Machine-readable slice contract for runner | `docs/planning-structured-slice-format.md`, Slither example | N/A | `NOT_TRANSFERRED` | `MISSING_ACCEPTABLE` | MEDIUM | ALIGNED | Schema only in Agent OS | `KEEP_AS_LINEAGE` |
| Workspace layout boundaries | `.agent-os/planning/`, `.agent-os/runs/`, orchestrator intakes | `docs/planning-workspace-layout.md`, `agent_os/paths.py` | `workspace_context` string in truth trace | `CONCEPTUAL_TRANSFER` | `WEAKER_IN_ADMISSIBLE` | HIGH | ALIGNED | No filesystem workspace discipline in Admissible | `ADD_TRUTH_TRACE_FIELD` for workspace snapshot id |
| Execution boundaries | No execution without gates; planning `no_execution` flags | `planning.py` manifest authority, `docs/v0-release-boundary.md` | Core thesis: evaluate before side effect; `side_effect_executed: false` in traces | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | — | `ADD_TESTS` for envelope→decision invariants |
| Closure artifacts | Fail-closed run end; placeholders = missing | `agent_os/validate.py`, `close_run()`, templates | `SMOKE_PASS`/`SMOKE_FAIL` on benchmark runs; truth trace `side_effect_executed` | `CONCEPTUAL_TRANSFER` | `WEAKER_IN_ADMISSIBLE` | MEDIUM | PARTIALLY_ALIGNED | No mission/audit/owner closure chain | `DOCUMENT_ONLY`; closure stays Agent OS or external orchestrator |
| Audit trails | Append-only decisions, provenance chain, audit verdict | `decisions/*.json`, `audit.md`, orchestrator `*-provenance.json` | `audit_trace` in decision output; `run_trace.schema.json`; truth trace decisions | `REFORMALIZED_STRONG` | `EQUIVALENT` (admission scope) | HIGH | ALIGNED | Weaker upstream artifact chain | `ADD_TRUTH_TRACE_FIELD` linking admission decisions to agent step ids (partially done) |
| Source-bounded evidence | Evidence from owner/registrar only; no LLM invention | `evidence-capture-boundaries-v0.md`, orchestrator transport | `evidence` block; `REQUEST_MORE_EVIDENCE`; rules_only missing-evidence signals | `REFORMALIZED_WEAK` | `WEAKER_IN_ADMISSIBLE` | HIGH | ALIGNED | Terminal dry-run trusts fixture envelopes, not live extraction | `PORT_AS_ADMISSIBLE_CONCEPT` — envelope builder must mark `source_trust` |
| Human responsibility | Owner remains responsible; closure ≠ truth | `docs/why-agent-os.md`, owner-decision templates | `human_responsibility` in envelope schema/spec | `REFORMALIZED_WEAK` | `EQUIVALENT` (doctrine) | HIGH | ALIGNED | Spec field; weak runtime enforcement | `ADD_SCHEMA_FIELD` if not in all Tier 1 cases |
| Approval scope | `AUTHORIZE_*` scopes next command only | Orchestrator CLI messages, decision records | `authority_context.approval_scope` (`execute_once`, `draft_only`, etc.) | `REFORMALIZED_STRONG` | `EQUIVALENT` | HIGH | ALIGNED | — | `ADD_TESTS` for scope mismatch → `REQUIRE_HUMAN_APPROVAL` |
| Authority vs capability | Planning disclaims execution; autonomy levels L0–L4 | `docs/autonomy-levels.md`, planning manifest | `authority_context` vs model capability in envelope + evaluator | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | — | Keep; extend Tier 1 cases |
| Reversibility | ADR / risk notes per choice | `architecture-decision-boundary.md` (weak impl) | `risk_context.reversibility`; rules_only checks | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | Agent OS ADR not implemented; Admissible stronger | `ADD_TESTS` |
| Blast radius | Planning risk notes | Planning templates | `risk_context.blast_radius` | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | — | `ADD_TESTS` |
| Evidence missing / sufficiency | Closure checks presence; quality in doctrine | `validate_run_for_closure`, orchestrator validation reports | `REQUEST_MORE_EVIDENCE`, `missing_evidence` in decision output | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | — | Benchmark tier 2+ for implicit evidence |
| Policy context | Planning constraints, non-goals | Planning `local-agentic-spec.md` | `policy_context` in envelope | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | — | `ADD_TESTS` for policy conflict cases |
| Side-effect classification | Implicit via planning gates | `no_execution` flags | `proposed_action.side_effect_type`, `expected_side_effect` | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | Core Admissible thesis | Keep |
| Safe alternatives / safer next step | Stop conditions in slices | Planning prose | `candidate_safer_next_steps`, `safer_next_step` in decision output | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | HIGH | ALIGNED | — | `ADD_TESTS` |
| No-side-effect dry-run discipline | Orchestrator never invokes executor | Orchestrator design | Terminal dry-run, long-run truth console, demo banners | `REFORMALIZED_STRONG` | `EQUIVALENT` | HIGH | ALIGNED | Live provider demos evaluate only; no mutation | `ADD_LONG_RUN_DEMO_REQUIREMENT` banner in all live paths |
| Traceability | Provenance JSON, manifest transitions | Orchestrator evidence chain | `run_trace.json`, truth trace, HTML viewers | `REFORMALIZED_STRONG` | `EQUIVALENT` (admission) / `WEAKER` (full run) | HIGH | ALIGNED | Multi-hour session not live-traced | `FUTURE_REPO_EXTRACTION` — envelope builder adapter |
| Benchmarkability | Explicitly excluded from Agent OS v0 | `docs/v0-release-boundary.md` | Full benchmark stack | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | MEDIUM | ALIGNED | Tier 1 seed only | Continue tier expansion per spec |
| Demo claim boundaries | v0 CLI scope doc | `v0-release-boundary.md` | `TIER_1_CLAIM_BOUNDARY`, `LONG_RUN_CLAIM_BOUNDARY`, demo-pack docs | `REFORMALIZED_STRONG` | `STRONGER_IN_ADMISSIBLE` | MEDIUM | ALIGNED | — | Keep |
| Long-run orchestration | Anti-orchestration; manual CLI transitions | `docs/planning-layer-doctrine.md` | **Not present** — by thesis | `INTENTIONALLY_OUT_OF_SCOPE` | `NOT_APPLICABLE` | HIGH | ALIGNED | — | `DO_NOT_PORT` |
| Separation from frontier model | External agent executes; OS structures | `docs/why-agent-os.md` | `ModelClient` protocol; frontier_direct baseline | `REFORMALIZED_STRONG` | `EQUIVALENT` | HIGH | ALIGNED | — | Keep |
| Prevention of hidden autonomous progression | Owner gates between stages | Orchestrator + planning transitions | Label precedence; no auto-execute in demos | `REFORMALIZED_WEAK` | `WEAKER_IN_ADMISSIBLE` | HIGH | ALIGNED | No stage gates in Admissible | Upstream orchestrator or manual demo script |
| Rollback / recovery expectations | ADR / slice stop conditions | Docs only | `rollback_available` in some envelopes | `CONCEPTUAL_TRANSFER` | `WEAKER_IN_ADMISSIBLE` | MEDIUM | ALIGNED | Weak both sides | `ADD_SCHEMA_FIELD` + tier 2 cases |
| Exact command/workspace mutation tracking | Evidence registrar, git snapshot allowlist | `agent_os/workspace.py` | Truth trace `execution_log`; terminal fixtures | `REFORMALIZED_WEAK` | `WEAKER_IN_ADMISSIBLE` | HIGH | PARTIALLY_ALIGNED | No live command capture | `FUTURE_REPO_EXTRACTION` — Cursor hook → envelope |
| Proposed / admitted / blocked / executed | Draft vs approved; planning states | Orchestrator + planning state machines | `action_candidates.execution_status`, decisions, `operational_admissibility_action`, `side_effect_executed` | `REFORMALIZED_STRONG` | `EQUIVALENT` (boundary) | HIGH | ALIGNED | Executed path not implemented (dry-run only) | `ADD_TRUTH_TRACE_FIELD` for `executed` vs `admitted` vs `blocked` |

---

## 6. Lost or Weakened Guarantees

Serious gaps for **Cursor Composer 2.5 Slither-like long-run demos**:

| Guarantee | Agent OS strength | Admissible today | Why it matters for long-run demo | Severity |
|-----------|-------------------|------------------|----------------------------------|----------|
| Goal → scope discipline | Strong intake + ambiguity flags | Single static `LONG_RUN_PROMPT` fixture | Agent can drift to deploy/refund/delete without upstream scope gate | **High** |
| Multi-stage owner authorization | `AUTHORIZE_*` chain before promotion | Per-envelope `REQUIRE_HUMAN_APPROVAL` only | Demo needs both planning promotion and per-action admission | **Medium** |
| Planning workspace / slice progression | Strong CLI + tests | Not in Admissible | Credible “build Slither-like” narrative needs plan artifacts or external tool | **High** |
| Live frontier output → envelope | N/A in Agent OS | Fixture-only (`terminal_dry_run_demo`) | No real Composer transcript ingestion | **Critical** |
| Fail-closed session closure | `validate_run_for_closure` | Smoke verdict on benchmark pack only | Cannot certify “long run ended cleanly” in Admissible alone | **Medium** |
| Source-bounded evidence at extraction | Strong orchestrator provenance | Envelope fields exist; builder unspecified | Live demo may admit actions on unverified agent claims | **High** |
| Hidden progression prevention | Gates between orchestrator stages | Admission only at envelope evaluate time | Agent could batch proposals without upstream gates | **Medium** |

**Acceptable losses (thesis-aligned):** full orchestrator runtime, planning workspace CLI inside Admissible, requirements promotion pipeline, `.agent-os/` workspace bootstrap as part of Admissible package.

---

## 7. Stronger-in-Admissible Guarantees

| Guarantee | What Admissible adds beyond Agent OS |
|-----------|--------------------------------------|
| **Canonical admission labels** | Five labels with explicit precedence — Agent OS had no equivalent for tool-call admission |
| **Action envelope schema** | Structured pre-execution object with policy, risk, authority, evidence — benchmarkable |
| **Deterministic scoring harness** | Label accuracy, false-allow, missing-escalation, confusion matrix — Agent OS excluded benchmarks |
| **Gold annotations separated from input** | Prevents label leakage in frontier baselines |
| **Frontier provider baselines** | Mock, HF, Gemini live paths with schema-constrained output |
| **Operational admissibility mapping** | `execute` / `block` / `request_approval` / `limit_scope` / `replace_with_safer_step` |
| **Truth trace model** | Long-run narrative tying agent steps → candidates → decisions → execution log |
| **Visual inspection** | HTML trace viewer, truth console — faster audit than markdown-only |
| **Claim boundaries embedded in artifacts** | Explicit non-claims on every smoke/demo output |
| **Import isolation enforced by tests** | AST boundary tests — stronger than Agent OS’s informal separation |
| **Side-effect typing at evaluation** | First-class `side_effect_type` / `expected_side_effect` — Agent OS implicit via planning flags |

---

## 8. Thesis Conflicts

These Agent OS primitives **must not** be ported into Admissible runtime without breaking the thesis:

| Primitive | Conflict if ported |
|-----------|-------------------|
| Full orchestrator pipeline (`agent_os/orchestrator.py`) | Turns Admissible into upstream governance orchestrator |
| Planning workspace CLI (`init` / `transition` / `decide`) | Reintroduces planning state machine inside admission layer |
| Fail-closed run closure as Admissible core | Conflates “run governance complete” with “action may execute” |
| Goal intake state machine inside evaluator | Blurs admission with requirements drafting |
| Auto-chained LLM → invoke progression | Violates “evaluate before side effect; don’t replace frontier loop” |
| `.agent-os/` workspace bootstrap in `admissible/` | Couples admission to historical filesystem protocol |
| `PLANNING_RUN_SLICE` importer / runner | Becomes execution orchestrator |

**Safe to port as concepts (not `agent_os` imports):** non_authority flags on traces, source_trust on evidence, append-only decision records, fail-closed validation of trace shape, vocabulary mapping docs.

---

## 9. Long-Run Cursor/Composer Implications

### What must exist for a credible end-to-end Cursor long-run demo

1. **Live or recorded frontier capture** — Composer/CLI transcript → proposed tool/commands (today: `AGENT_STEP_SOURCE_TRUST = unverified_agent_output` fixture only).
2. **Envelope builder adapter** — maps tool proposals to `action_envelope.schema.json` with explicit `source_trust` and `provenance` (not in repo as standalone module).
3. **Per-proposal admission evaluation** — rules_only and/or model-assisted evaluator on each envelope (exists; needs live feed).
4. **Truth trace emission** — extend `admissible/long_run_truth.py` with non-fixture `source_type` (partial schema exists).
5. **Demo claim boundary** — retain `LONG_RUN_CLAIM_BOUNDARY`; never imply benchmark or production certification.
6. **Thesis-aligned composition doc** — how external Cursor loop calls Admissible without importing `agent_os`.

### What can remain manual / fixture-backed

- Agent OS goal intake and requirements promotion (run separately via `agent_os` CLI if needed for narrative).
- Planning slice content (`examples/planning-workspace-slither-like/`).
- Gold labels for demo envelopes (hand-authored).
- Slither game implementation itself (frontier agent responsibility).

### What needs schema or truth trace support

| Field / artifact | Purpose |
|------------------|---------|
| `agent_steps.source_type: "live_cursor" \| "fixture" \| "recording"` | Distinguish demo modes |
| `action_candidates.envelope_builder_version` | Reproducibility |
| `execution_log.event: "admitted" \| "blocked" \| "executed"` | Separate admission from execution |
| `long_run.session_id` + `workspace_snapshot_ref` | Tie to workspace state without Admissible owning `.agent-os/` |
| Envelope `provenance.source_bounded: boolean` | Carry Agent OS extraction discipline |

---

## 10. Recommended Next Actions

### P0 (minimal, thesis-aligned)

1. **Document cross-layer long-run composition** — one page: Cursor loop → envelope builder → Admissible evaluate → optional execute; Agent OS optional upstream. (`DOCUMENT_ONLY`)
2. **Add truth-trace fields** for `source_type` live vs fixture and `execution_status` admitted/blocked/executed distinction. (`ADD_TRUTH_TRACE_FIELD`)
3. **Keep boundary tests green** — no `agent_os` imports. (`ADD_TESTS` maintenance)

### P1 (closes long-run demo gaps without orchestrator port)

4. **Envelope builder sketch module** in `admissible/` (pure function: terminal/tool JSON → envelope) — no `agent_os` import. (`PORT_AS_ADMISSIBLE_CONCEPT`)
5. **Expand terminal dry-run pack** with Slither-relevant cases (local file write, npm install, git push). (`ADD_LONG_RUN_DEMO_REQUIREMENT`)
6. **Tier 1 cases** covering `approval_scope` mismatch and `source_trust=unverified`. (`ADD_TESTS` + cases)

### P2 (future)

7. **Recording adapter** for Cursor CLI output → truth trace. (`FUTURE_REPO_EXTRACTION`)
8. **Benchmark tier 2** partially implicit evidence per `Admissible_BENCHMARK_SPEC.md`.
9. **Model-assisted Admissible evaluator** (trace descriptor exists; not implemented).

**Explicitly not recommended:** merge `agent_os/orchestrator.py` into Admissible; rename repo; delete `agent_os/`; runtime import bridge.

---

## 11. Non-Claims

- This audit **does not** prove Admissible benchmark performance or label accuracy on production workloads.
- This audit **does not** require runtime reuse of `agent_os` modules for thesis validity.
- This audit **does not** authorize deleting, moving, or deprecating `agent_os/`.
- This audit **does not** certify that the Long-Run Truth Console v0 represents a real Cursor Composer 2.5 session.
- This audit **does not** evaluate the external `agent-os-runner-experimental` repository.

---

## Appendix: Verification commands

```powershell
# Import boundary (must pass)
python -m unittest tests.test_admissible_boundary -v

# Admissible unit tests
python -m unittest discover -s tests -p "test_admissible_*.py" -v

# Agent OS suite (lineage; separate from Admissible boundary)
python -m unittest tests.test_agent_os -v

# Long-run truth console artifact
python -m admissible.runner.long_run_truth_console --out benchmark/reports/admissible_long_run_truth_console.html

# Terminal dry-run demo
python -m admissible.runner.terminal_dry_run_demo --demo-pack benchmark/terminal_agent_dry_run/demo-pack.json
```
