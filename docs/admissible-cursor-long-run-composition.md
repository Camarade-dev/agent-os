# Admissible / Cursor Long-Run Composition Contract v0

**Slice:** `ADMISSIBLE_CURSOR_LONG_RUN_COMPOSITION_AND_ENVELOPE_BUILDER_V0`  
**Date:** 2026-07-08  
**Related:** [`admissible-rigor-transfer-audit.md`](admissible-rigor-transfer-audit.md), [`admissible-agent-os-lineage.md`](admissible-agent-os-lineage.md), [`Admissible_THESIS.md`](Admissible_THESIS.md)

---

## Status and claim boundary

This document defines a **composition contract** between frontier agent capability (Cursor Composer 2.5 / Cursor CLI), Admissible action admission, and TruthTrace rendering for long-run software-agent demos.

| Property | Value |
|----------|-------|
| **Scope** | Cross-layer data flow and trust model for fixture-backed long-run demos |
| **Claim boundary** | Composition specification and offline envelope builder v0 only; not a live Cursor integration, not a benchmark result, not an orchestrator |
| **Side effects** | None in this slice — all paths are `proposed_only` until an outer executor explicitly runs admitted actions |
| **Runtime dependency on `agent_os`** | **None.** Admissible must not import `agent_os`. Agent OS lineage is conceptual only. |

---

## Layer definitions

### Capability layer — Cursor Composer 2.5 / Cursor CLI

- Proposes tool calls, shell commands, file edits, deployment steps, and status claims.
- Operates over a workspace with model reasoning and multi-step context.
- Output is **raw agent text** (terminal transcript, tool-call blocks, notes).
- Does **not** decide organizational authority, evidence sufficiency, or execution permission.

### Admission layer — Admissible

- Receives **action envelopes** (structured proposed side-effecting operations).
- Evaluates authority, evidence, policy, risk, and provenance fields.
- Emits one of five canonical admission labels: `ALLOW`, `ALLOW_WITH_LIMITS`, `REQUEST_MORE_EVIDENCE`, `REQUIRE_HUMAN_APPROVAL`, `REFUSE`.
- Does **not** run the full long-run agent loop, planning workspace lifecycle, or upstream goal intake.

### Orchestration layer — external / deferred

- Owns session loop, step scheduling, and optional execution after admission.
- May be Cursor itself, a custom harness, or (optionally, upstream) Agent OS planning lineage.
- Admissible evaluates **per-action** admission; orchestration decides **when** to propose and **whether** to execute after admission.

### Lineage layer — Agent OS (historical, optional upstream)

- Provides governed-delegation vocabulary: goal intake, requirements promotion, planning workspaces, fail-closed closure.
- **Not a runtime dependency** for Admissible or this composition slice.
- Useful as upstream governance inspiration for future paired demos; must not be ported wholesale into Admissible.

---

## Non-goals (this slice)

- Live Cursor CLI capture or network provider calls.
- Executing shell commands parsed from raw agent output.
- Porting Agent OS orchestrator, planning runtime, or `.agent-os/` workspace machinery.
- Building a simultaneous paired-run comparator or full long-run orchestrator.
- LLM-based extraction from arbitrary natural language.
- Collapsing Admissible back into Agent OS.

---

## Data flow

```
raw agent output (unverified)
        │
        ▼
  envelope builder v0 (rule-based, deterministic)
        │
        ├──► action candidate(s)  ── interpretation + field provenance
        │
        └──► action envelope(s)   ── schema-shaped, rules-only evaluable
                │
                ▼
        rules_only evaluator (Admissible)
                │
                ▼
        admission decision + audit trace
                │
                ▼
        TruthTrace (Long-Run Truth Console)
                │
                └──► proposed / blocked / admitted-not-executed / executed-after-admission
                     (v0: proposed_only + admission_evaluated only)
```

### Stage semantics

| Stage | Input | Output | Deterministic? |
|-------|-------|--------|----------------|
| Raw capture | Agent session text | `raw_output` string | N/A (external) |
| Candidate extraction | `raw_output` + optional metadata | `action_candidates[]` | **Yes** (rule-based v0) |
| Envelope construction | Candidate + defaults | `action_envelope` dict | **Yes** (template + observed fields) |
| Admission | Envelope | `decision` label + reasons | **Yes** (rules_only) |
| Truth assembly | Steps + candidates + decisions | `TruthTrace` JSON | **Yes** (fixture-backed v0) |

Heuristic elements (explicitly labeled): action-type classification from regex patterns, missing-evidence defaults per action class, safer-next-step suggestions for delete/archive cases.

---

## Trust model

| Artifact | Trust level | Role |
|----------|-------------|------|
| Raw agent output | **`unverified_agent_output`** | Provenance only; never authority |
| Parsed tool/command | **Interpretation** | May be wrong or incomplete |
| User line (`User: …`) | **Observed** from output | Intent hint, not approval |
| Note lines (`Note: …`) | **Observed** | Evidence-gap hints |
| Envelope enriched fields | **Inferred or defaulted** | Must carry `field_provenance` |
| Admission decision | **Derived** | From envelope + rules_only; auditable |
| Execution log | **Ground truth for side effects** | v0: always `side_effect_executed: false` |

### Field provenance (envelope builder output)

Each candidate/envelope distinguishes:

- **`observed`** — extracted verbatim or by structural parse (user text, tool name, JSON args, notes).
- **`inferred`** — rule-based classification (action_type, side_effect_type, missing evidence from notes).
- **`missing`** — required envelope fields not present in raw output (explicit gaps).
- **`defaulted`** — conservative template values (actor, principal, workflow placeholders).

---

## Execution model

- **Default:** `execution_status: proposed_only` — no side effect runs.
- Admission evaluates **whether** an action may execute; it does **not** execute.
- An **outer executor** (future: Cursor gate, custom runner) must explicitly invoke admitted actions.
- Blocked or evidence-requested actions must not silently downgrade to execution.

---

## TruthTrace integration

Existing v0 fields (in `admissible/long_run_truth.py`) are sufficient for the baseline console:

| Field | Location | v0 values |
|-------|----------|-----------|
| `source_type` | `agent_steps[]` | `fixture`, `pasted`, `captured_cli`, `live_cursor` |
| `source_trust` | `agent_steps[]` | `unverified_agent_output` |
| `execution_status` | `action_candidates[]` | `proposed_only` (v0 default) |

Builder-specific fields on `action_candidates[]` (when produced by envelope builder):

| Field | Values |
|-------|--------|
| `extraction_method` | `fixture_mapping`, `rule_based_v0`, `manual_review` |
| `extraction_confidence` | `low`, `medium`, `high` |

Future `execution_status` extensions: `blocked`, `admitted_not_executed`, `executed_after_admission`.

The Long-Run Truth Console renders: raw output → proposed action → admission decision → operational admissibility action → execution log (no execution in v0).

---

## Envelope builder v0

**Module:** `admissible/long_run_envelope_builder.py`

**Input:**

- `raw_output: str`
- optional `long_run_prompt: str`
- optional `source_metadata`:
  - `source_type`: `fixture` | `pasted` | `captured_cli` | `live_cursor`
  - `frontier_agent_label`: e.g. `Cursor Composer 2.5`
  - `workspace_context`: e.g. `local_slither_demo_workspace`

**Output:**

- `action_candidates[]` — lightweight structured interpretations
- `envelopes[]` — full schema-shaped dicts ready for `evaluate_envelope()`

**Supported action patterns (v0):**

| Pattern | action_type | Expected admission tendency |
|---------|-------------|----------------------------|
| Production deploy / prepare deployment | `deploy_code` / `prepare_deploy` | `REQUIRE_HUMAN_APPROVAL` |
| Dependency install (`npm install`, `pip install`) | `install_dependency` | `REQUEST_MORE_EVIDENCE` |
| File/folder deletion | `delete_file` / `delete_folder` | `ALLOW_WITH_LIMITS` (archive path) or `REQUIRE_HUMAN_APPROVAL` |
| Git commit / push | `git_commit` / `git_push` | `REQUEST_MORE_EVIDENCE` / `REQUIRE_HUMAN_APPROVAL` |
| Production-ready claim | `claim_status` | `REQUEST_MORE_EVIDENCE` |
| Safe local file edit | `edit_file` | `ALLOW` or `ALLOW_WITH_LIMITS` |
| Unknown / ambiguous | `unknown` | `REQUEST_MORE_EVIDENCE` (never default `ALLOW`) |

Conservative default: unknown patterns do **not** silently become `ALLOW`.

### Multi-action freeform extraction (v0.3)

A pasted, non-table Cursor-class response (i.e. anything that is not a
production-readiness table report, see `_is_production_readiness_report`)
is broken into independently classifiable segments before falling back to
a single whole-document candidate: explicit `Proposed command:` /
`Command:` blocks, bare indented commands, fenced shell blocks, `Proposed
tool call:` blocks, numbered/bulleted list items, and finally remaining
narrative lines (structural labels like `User:`/`Status:`/`Note:` and
headings are skipped). Each segment is independently checked for
negation/conditional phrasing (`I will not …`, `do not …`, `not yet`,
`unless approved`, `nothing was executed`, …) before classification, so a
mixed response can yield several positive candidates (e.g. an install, a
push, and a local edit in one paste) while a negated mention of the same
action never becomes a positive candidate. Only when **no** segment yields
a positive classification does extraction fall back to the single
whole-document `unknown`/`REQUEST_MORE_EVIDENCE` candidate described above.

**Regression harness:** `admissible/runner/extraction_lab.py` runs this
pipeline over
`benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses/`
against `expected_extractions.json` (minimum candidate count, expected/
forbidden action types, expected/forbidden decisions per fixture) and
reports pass/fail as JSON (and optionally Markdown). See
`docs/admissible-supervised-run-loop.md` for how this feeds the run loop's
paste-and-ingest path.

---

## Boundary with Agent OS

| Concern | Agent OS | Admissible (this slice) |
|---------|----------|-------------------------|
| Goal intake / requirements | Yes | Out of scope |
| Planning slices | Yes | Out of scope |
| Per-action admission | Weak / absent | **Core** |
| Envelope builder from raw output | Absent | **v0 added here** |
| Import relationship | Independent | **Must not import `agent_os`** |

Shared vocabulary (evidence, audit, admissible) refers to **different artifacts**. See [`admissible-agent-os-lineage.md`](admissible-agent-os-lineage.md).

---

## Future extension points

1. **Live Cursor capture** — stream CLI output into `source_type: live_cursor` agent steps.
2. **Manual paste/import** — `source_type: pasted` for ad-hoc review.
3. **Paired-run video** — compare frontier-direct vs Admissible-gated runs (separate slice).
4. **Optional Agent OS upstream planning** — external orchestrator produces scope-bound prompts; Admissible still owns admission.
5. **Envelope builder v1** — broader pattern library, structured tool-call AST, human review queue (`extraction_method: manual_review`).

---

## Explicit statement

**Admissible has no runtime dependency on `agent_os`.** This composition slice adds an offline, rule-based bridge from raw Cursor-class agent output to action envelopes. It preserves the Admissible / Agent OS boundary established in the rigor transfer audit verdict `SPLIT_LAYER_UNEVEN_TRANSFER`.
