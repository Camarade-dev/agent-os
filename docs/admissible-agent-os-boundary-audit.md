# Admissible / Agent OS Boundary Audit

**Date:** 2026-07-08  
**Repo:** `agent-os` (historical name)  
**Auditor scope:** `admissible/`, `benchmark/`, Admissible runners/tests/docs, and their relationship to `agent_os/`

## Executive summary

The repository hosts **two sibling systems** with **no active runtime dependency** from Admissible into Agent OS:

| Question | Result |
|----------|--------|
| Does `admissible/` import `agent_os`? | **No** (AST-verified; comments/docstrings may mention `agent_os`) |
| Does `benchmark/` import `agent_os`? | **No** |
| Do Admissible tests/runtime paths load `agent_os.*`? | **No** (verified by import-boundary tests) |
| Is the relationship documented? | **Partially** — lineage doc existed; this audit and hardened tests close the gap |
| Are there duplicated concepts? | **Yes** — vocabulary overlap (evidence, owner decision, “admissible”) — documented, not merged |

**Diagnostic flags (pre-cleanup):**

- `BOUNDARY_IMPORTS_CLEAN` — imports are clean; no runtime fix required
- `BOUNDARY_DOCS_AMBIGUOUS` — README and repo layout under-emphasize Admissible; orchestrator docs reuse “admissible for promotion”
- `BOUNDARY_README_NEEDS_CLARIFICATION` — README leads with Agent OS; dual-system framing improved in this slice
- `BOUNDARY_TESTS_NEED_HARDENING` — per-module string checks existed; centralized AST boundary test added
- `BOUNDARY_CLEANUP_TOO_BROAD` — not applicable; no broad migration performed

## Canonical boundary doctrine

These statements are authoritative for this repository:

1. **Admissible is the active benchmarkable action-admission layer.**
2. **Agent OS is historical lineage and substrate** (governed-delegation CLI, planning workspaces, evidence registrar).
3. **Admissible modules must not import `agent_os`.**
4. **The repo name is historical** and does not imply Admissible is a submodule of Agent OS.
5. **Shared repo does not mean shared runtime authority** — co-location is organizational; object models and execution paths are separate.

See also: [`admissible-agent-os-lineage.md`](admissible-agent-os-lineage.md).

---

## 1. Import boundary audit

### Method

- Ripgrep for `from agent_os` / `import agent_os` across `admissible/` and `benchmark/`
- AST walk of all `*.py` under `admissible/` and `benchmark/` (import nodes only; ignores comments/docstrings)
- Runtime check: importing Admissible modules must not register `agent_os.*` in `sys.modules`

### Results

| Area | Python files | `agent_os` imports |
|------|--------------|-------------------|
| `admissible/` | 15 modules | **0** |
| `benchmark/` | 2 modules (`benchmark/scoring/`) | **0** |

**Allowed cross-boundary direction today:**

```
benchmark.scoring  ──imports──▶  admissible.decision, admissible.evaluator.rules_only
admissible.*       ──imports──▶  benchmark.scoring.score_decisions
```

Neither direction touches `agent_os`. Agent OS does not import Admissible.

**Text mentions only (not imports):**

- `admissible/__init__.py`, `admissible/decision.py`, `admissible/harness/__init__.py` — boundary documentation in docstrings
- `benchmark/scoring/metrics.md` — explicit non-modification statement for Agent OS files

### Test / runtime paths

Admissible-focused tests live under `tests/test_admissible_*.py` and do **not** import `agent_os`. The Agent OS suite (`tests/test_agent_os.py`) is separate and only exercises `agent_os.*`.

Admissible CLI entry points (`python -m admissible.runner.*`, `python -m admissible.harness.*`, `python -m benchmark.scoring.score_decisions`) resolve imports within `admissible` + `benchmark` only.

---

## 2. Classification by audit category

### ACTIVE_ADMISSIBLE_CORE

| Path | Role |
|------|------|
| `admissible/__init__.py` | Package surface; exports `AdmissionDecision` |
| `admissible/decision.py` | Canonical admission labels and precedence |
| `admissible/evaluator/rules_only.py` | Rules-only reference evaluator |
| `admissible/evaluator/__init__.py` | Evaluator exports |
| `admissible/trace.py` | Run trace builder |
| `docs/Admissible_THESIS.md` | Design thesis |
| `docs/Admissible_ACTION_ENVELOPE.md` | Action envelope spec |
| `docs/Admissible_BENCHMARK_SPEC.md` | Benchmark design |

### ACTIVE_ADMISSIBLE_BENCHMARK

| Path | Role |
|------|------|
| `benchmark/schemas/*.schema.json` | Envelope, decision, gold, trace schemas |
| `benchmark/cases/tier_1_enriched/` | 25 Tier 1 enriched seed cases |
| `benchmark/annotations/gold_labels.jsonl` | Gold annotations |
| `benchmark/scoring/score_decisions.py` | Deterministic scoring metrics |
| `benchmark/scoring/metrics.md` | Metric definitions |
| `benchmark/prompts/frontier_direct_decision.md` | Frontier-direct prompt template |
| `benchmark/examples/` | Schema conformance examples (not a case set) |
| `benchmark/README.md`, `benchmark/cases/README.md` | Benchmark docs |

### ACTIVE_ADMISSIBLE_DEMO

| Path | Role |
|------|------|
| `admissible/runner/baseline_runner.py` | Single-case frontier-direct baseline |
| `admissible/runner/compare_runner.py` | Multi-system comparison runner |
| `admissible/runner/demo_trace.py` | Demo trace + HTML generator |
| `admissible/runner/model_clients.py` | HF / Gemini / env-http model clients |
| `admissible/runner/terminal_dry_run_demo.py` | Terminal Agent Dry-Run Demo v0 |
| `admissible/runner/long_run_truth_console.py` | Long-Run Truth Console v0 CLI |
| `admissible/long_run_truth.py` | Long-run truth trace logic |
| `admissible/harness/viewer.py`, `viewer.html` | Visual trace viewer |
| `admissible/harness/truth_console.py`, `truth_console.html` | Long-run truth console HTML |
| `admissible/harness/clean_trace.py` | Trace redaction / clean export |
| `admissible/harness/provider_settings.py`, `.html` | Local provider settings helper |
| `benchmark/reports/demo-pack.json`, `demo-script.json`, `*.md` | Curated demo narrative |
| `benchmark/terminal_agent_dry_run/` | Terminal dry-run demo pack + fixtures |

### AGENT_OS_LEGACY

| Path | Role |
|------|------|
| `agent_os/cli.py` | `agent-os` CLI |
| `agent_os/orchestrator.py` | Planning/orchestration substrate (large) |
| `agent_os/planning.py` | Planning workspace registrar |
| `agent_os/workspace.py` | Run workspace + evidence registrar |
| `agent_os/validate.py` | Fail-closed closure validation |
| `agent_os/paths.py` | Filesystem paths |
| `agent_os/templates/` | Run + planning markdown templates |
| `tests/test_agent_os.py` | Agent OS test suite |
| `docs/why-agent-os.md`, `docs/thesis.md`, `docs/v0-release-boundary.md` | Agent OS protocol docs |
| `docs/planning-*.md`, `docs/orchestrator/` | Planning/orchestrator doctrine |
| `docs/dogfood-*.md`, `docs/evidence-capture-*.md` | Agent OS dogfood + evidence doctrine |
| `examples/planning-workspace-slither-like/` | Planning workspace example |

### SHARED_REPO_INFRA

| Path | Role |
|------|------|
| `pyproject.toml` | Packages both `agent_os*` and `admissible*`; CLI entry `agent-os` only |
| `README.md` | Top-level onboarding (both systems) |
| `CHANGELOG.md` | Release notes (v0.1.0 Agent OS–centric) |
| `tests/` | Split suites: `test_agent_os.py` vs `test_admissible_*.py` |
| `.gitignore` | `.agent-os/`, `.admissible/`, generated benchmark reports |
| `docs/admissible-agent-os-lineage.md` | Canonical lineage/boundary doc |

### AMBIGUOUS_NEEDS_RENAME_OR_DOC

| Path | Issue | Recommendation |
|------|-------|----------------|
| Repo name `agent-os` | Implies single product | Documented: historical; see lineage doc + README lead |
| `agent_os/orchestrator.py` — “admissible for promotion” | Collides with Admissible product name | Keep code; cross-link vocabulary section in lineage doc |
| `docs/orchestrator/goal-intake-artifact.md` | Uses Agent OS “admissible” phrasing | Label as Agent OS planning vocabulary in lineage doc |
| `README.md` “Repository layout” | Previously listed only `agent_os/` | Updated to show `admissible/` + `benchmark/` |
| `CHANGELOG.md` | No Admissible milestones | Future entry when versioning Admissible separately |
| `pyproject.toml` description | Agent OS–only wording | Optional future tweak; out of scope for this slice |

### CANDIDATE_FOR_FUTURE_EXTRACTION

| Path | Rationale |
|------|-----------|
| `admissible/` + `benchmark/` + Admissible docs/tests | Self-contained benchmark harness; could become its own repo or package |
| `agent_os/` | Stable v0.1.0 CLI substrate; could remain as lineage archive |

Extraction is **not** recommended until Admissible versioning and release boundaries are defined.

---

## 3. Duplicated concepts (confusion risk)

| Concept | Agent OS | Admissible | Same? |
|---------|----------|------------|-------|
| “Admissible” | Planning artifact “admissible for promotion” | Action may execute at boundary | **No** — homonym |
| Owner decision | Promote planning artifact / record workflow decision | `REQUIRE_HUMAN_APPROVAL` on a side-effecting action | **Related, not interchangeable** |
| Evidence | Markdown registrar under `.agent-os/runs/` | Fields inside `action_envelope` | **Different object model** |
| Validation / closure | `validate_run_for_closure`, fail-closed run close | `evaluate_envelope`, admission labels | **Different semantics** |
| Audit | Run audit verdict template | `audit_trace` on decision output | **Different artifacts** |

No code sharing exists for these concepts today — overlap is **vocabulary and discipline**, not duplicated implementations.

---

## 4. README posture (question 7)

Before this audit slice, the README:

- **Title and lead:** Agent OS v0.1.0
- **Also contained:** substantial Admissible quickstart (providers, tests, docs links)
- **Ambiguity:** Repository layout section implied the repo was only `agent_os/`

The README describes **both** systems but historically **foregrounded Agent OS**. This slice clarifies dual-system framing at the top and expands the layout section.

---

## 5. Smallest effective cleanup (applied)

1. **This audit report** — explicit classification and import evidence
2. **Strengthened** [`admissible-agent-os-lineage.md`](admissible-agent-os-lineage.md) — canonical boundary language + import rule
3. **README** — dual-system intro and repository layout
4. **`tests/test_admissible_boundary.py`** — AST import scan + package-wide `sys.modules` guard

**Not done (intentionally):**

- No deletion or move of `agent_os/`
- No repo rename
- No Admissible semantic changes
- No broad refactors of orchestrator “admissible for promotion” strings

---

## 6. Verification commands

```powershell
# Boundary tests only
python -m unittest tests.test_admissible_boundary -v

# Full Admissible-focused suite (from README)
python -m unittest tests.test_admissible_decision tests.test_admissible_rules_only tests.test_admissible_scoring tests.test_admissible_baseline_runner tests.test_admissible_compare_runner tests.test_admissible_trace tests.test_admissible_visual_trace_viewer tests.test_admissible_demo_pack tests.test_admissible_demo_trace tests.test_admissible_demo_script tests.test_admissible_boundary -v
```

---

## 7. Acceptance checklist

| Criterion | Status |
|-----------|--------|
| Relationship clear in docs | Yes |
| No Admissible runtime dependency on `agent_os` | Yes |
| Ambiguous files identified | Yes (table above) |
| Boundary tests pass | Run after commit |
| Admissible demo/test paths unchanged | Yes (docs/tests only) |
| No large deletion or migration | Yes |
| Working tree clean after commit | Pending user commit step |
