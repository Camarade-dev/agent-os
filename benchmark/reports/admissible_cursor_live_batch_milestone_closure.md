# Admissible — Cursor Live Batch Milestone Closure

**Slice:** `ADMISSIBLE_DEMO_020_CURSOR_LIVE_BATCH_MILESTONE_CLOSURE`  
**Date:** 2026-07-09  
**Status:** checkpoint closed (documentation only; no provider calls, no shell/npm/deploy/network automation, no admission/executor/UX changes, no commit)

---

## Milestone verdict

**`CURSOR_LIVE_STRUCTURED_RUN_USABLE_WITH_BATCH_EXECUTION`**

Related fix status: **`LIVE_BATCH_EXECUTION_CONTENT_GUARD_FIXED`**

A supervised, human-led Control Surface session completed a live Cursor structured-response loop and applied admitted local file writes through explicit batch execution. Final live retry: **Last batch: 3 succeeded, 0 failed** (`index.html`, `style.css`, `game.js`).

This is a real milestone. It is **not** the final Admissible proof. It demonstrates a bounded, supervised local side-effect loop with live agent output — not long-running autonomous task completion, frontier-model reliability, or production readiness.

---

## What was demonstrated

Admissible now demonstrates a **live supervised admission layer for local side-effecting agent proposals**: a live coding agent proposes structured local file operations; Admissible gates them; only admitted operations can be executed through a bounded, auditable channel with evidence.

### Supervised loop (observed end-to-end)

| Step | Mechanism | Result |
|------|-----------|--------|
| 1. User provides a goal | `POST /api/session/goal` | Goal intake; instruction write blocked until goal exists (slice 014) |
| 2. Admissible generates a bounded instruction for Cursor | Bridge writes `.admissible/next-agent-instruction.md` | Turn-bound instruction packet derived from goal |
| 3. Cursor writes only `.admissible/agent-response.md` | External Cursor agent | Three `ADMISSIBLE_STRUCTURED_OPERATION` blocks; no direct target-file writes |
| 4. Admissible ingests the response | `POST /api/session/run_loop/bridge/ingest_response` | Structured ops extracted; bridge session/turn binding enforced (slice 016) |
| 5. Structured local file operations extracted | Extraction + evaluation | 3× admitted `create_file` actions |
| 6. Ingestion does not write files | Mission summary + workspace check | `side_effect_executed_by_admissible: false`; game files absent after ingest |
| 7. Actions admitted and shown ready to execute locally | Execution review UX (slice 018) | Ready-to-execute panel; per-action eligibility visible |
| 8. Human explicitly triggers batch execution | `execute_bounded_local_batch` | Operator-initiated; no auto-execute on ingest |
| 9. Bounded executor writes local files | `bounded_executor` | Each write inside workspace jail |
| 10. Each write emits evidence including sha256 | Evidence records | `local_file_written`, `workspace_scope_attested` per file |

### Supporting slice evidence

| Area | Evidence |
|------|----------|
| Goal-first UX (014) | Blank session blocks instruction until goal submitted |
| Sample demotion / safe load (015) | Examples collapsed; safe-load refuses non-empty sessions without `force` |
| Bridge/session binding (016) | `bridge-state.json` binds `session_id` and turn; stale ingest blocked |
| Live structured ingest (017) | Per-file bounded execute path validated live |
| Execution review + batch UX (018) | Workspace persistence; explicit batch execute control |
| Content guard fix (019) | Path-aware `write_file` content policy; harmless goal-constraint prose no longer false-positives on HTML/CSS |

Prior reports: [admissible_cursor_live_structured_run_retry.md](./admissible_cursor_live_structured_run_retry.md) (017), [admissible_cursor_live_batch_content_guard_review.md](./admissible_cursor_live_batch_content_guard_review.md) (019 fix + offline 3/3 regression).

---

## What was not demonstrated

Do **not** infer any of the following from this milestone:

| Not claimed | Rationale |
|-------------|-----------|
| Autonomous long-running task success | Single supervised turn; operator present at every gate and execute step |
| Benchmark-level SOTA comparison | No paired frontier-direct vs Admissible-gated run; no scored benchmark suite |
| General software-engineering autonomy | One narrow scaffold scenario (vanilla browser game files); no refactor, debug loop, or multi-feature delivery |
| Frontier-model reliability solved | One successful live path; no adversarial extraction; no repeated-run statistics |
| Production readiness | No deploy, CI, packaging, or environment promotion |
| Product-grade UX | Known polish gaps (workspace picker, batch ergonomics, queue display) remain demo-acceptable, not product-grade |
| Autonomous deploy/test/build capability | Shell, npm, git, deploy, and network remain outside bounded-local execution unless future policy explicitly admits them |

Also unchanged:

- Admissible does not call model providers; Cursor is external.
- Admission rules were not weakened for this checkpoint.
- Multi-turn plan progress, evidence accumulation across turns, and blocked-action recovery in a live loop are not yet proven end-to-end.

---

## Why this milestone still matters

Before slices 014–019, the canonical demo was **`DEMO_READY_WITH_SCRIPTED_LIMITS`**: a coherent offline supervised loop over fixtures, with live Cursor and real side effects outside the readiness claim.

This milestone closes a specific gap: **live structured agent output → admission → human-approved bounded execution → verifiable local artifacts**, in one session, without ingest auto-execution and without weakening gates.

That is the minimum credible substrate for “Admissible as a side-effect gate in front of a real agent” — even though it is only one turn and one scenario. It separates:

1. **Capability** — Cursor can propose structured local writes  
2. **Permission** — Admissible admits or blocks before any write  
3. **Execution** — bounded executor applies only explicitly invoked admitted ops  

The content-guard fix matters because a false positive on harmless constraint echo would have made the batch path look broken while the admission layer was correct — a trust failure distinct from gate logic.

This is a **necessary substrate**, not the final frontier or long-running autonomy proof.

---

## Current system status

| Layer | Status |
|-------|--------|
| Offline scripted supervised loop | **`DEMO_READY_WITH_SCRIPTED_LIMITS`** (slices 001–006; canonical e2e regression) |
| Live Cursor structured single-turn + batch execute | **`CURSOR_LIVE_STRUCTURED_RUN_USABLE_WITH_BATCH_EXECUTION`** (this milestone) |
| Batch content guard (HTML/CSS/JS prose vs real network refs) | **`LIVE_BATCH_EXECUTION_CONTENT_GUARD_FIXED`** |
| Multi-turn governed continuation | **Not yet demonstrated** |
| Long-run autonomous completion | **Out of scope / not proven** |

**Tests (at closure time):** `python -m pytest tests/ -k admissible -q` → **834 passed**, 1258 deselected, 156 subtests passed.

---

## Remaining gaps before the final Admissible demo

1. **Multi-turn live loop** — second and subsequent turns with plan progress, stale-response protection across turns, and evidence carry-forward under live (not fixture) agent phrasing.
2. **Evidence-grounded continuation** — cross-turn evidence visible and usable for re-evaluation; unknown `reversibility` / `business_authority` signals handled in live flow.
3. **Blocked-action recovery** — clear operator path when an action is `REFUSE`, needs evidence, or batch partial-failure; live recovery narrative not yet rehearsed.
4. **Plan gate closure across turns** — offline regression covers gates; live Cursor compliance with gate-resolution packets unproven.
5. **Bounded verification commands** — admitted local checks (e.g. file presence, simple validators) without opening shell/network/deploy.
6. **UI polish** — `structured_operation_count`, queue `target_path` column, workspace picker, copy-Cursor-prompt shortcut.
7. **Repeated-run confidence** — single successful live batch; no flake or phrasing-drift statistics.
8. **Broader extraction** — adversarial or messy agent responses; mixed structured + natural-language turns.
9. **Frontier comparison and long-running benchmark** — honest paired runs and admission metrics over extended horizons.

None of these invalidate this milestone; they bound what the next demo narrative can honestly claim.

---

## Recommended next arc: multi-turn governed continuation

Move from **single-turn structured local file proposal** to a **bounded multi-turn supervised loop** where:

- each turn produces admitted proposals only;
- the operator explicitly gates every side effect;
- plan progress and evidence accumulate across turns;
- blocked or partial-failure states have a defined recovery path;
- verification stays inside admitted bounded-local policy until a future slice explicitly widens it.

Policy boundary: continue gating each side effect. No shell/network/deploy execution unless explicitly admitted by a future policy slice. Keep admission rules strict; extend orchestration, evidence, and UX only.

---

## Recommended next slices

| Slice | Intent |
|-------|--------|
| `ADMISSIBLE_RUN_021_MULTI_TURN_RUN_TIMELINE` | Persist turn counter, timeline, and queue state across bridge ingest cycles in one session |
| `ADMISSIBLE_RUN_022_EVIDENCE_GROUNDED_CONTINUATION` | Cross-turn evidence records drive re-evaluation and continuation decisions |
| `ADMISSIBLE_DEMO_023_MULTI_TURN_LOCAL_BUILD` | Human-led live Cursor rehearsal: 2–3 turns (e.g. scaffold → minimal game loop → local verify) |
| `ADMISSIBLE_DEMO_024_BLOCKER_AND_RECOVERY_LOOP` | Live path when one op is refused or needs evidence; operator supplies evidence or skips without breaking session |
| `ADMISSIBLE_EXECUTION_025_BOUNDED_VERIFICATION_COMMANDS` | Admitted local verification actions (no shell/network/deploy unless future policy admits) |
| `ADMISSIBLE_UX_026_PRODUCT_GRADE_RUN_TIMELINE` | Plan steps, completed vs pending, next operator action surfaced in Control Surface |
| `ADMISSIBLE_DEMO_027_FRONTIER_MODEL_LONG_RUNNING_COMPARISON` | Paired honest comparison: frontier-direct vs Admissible-gated on a bounded multi-turn scenario |
| `ADMISSIBLE_BENCH_028_LONG_RUNNING_ADMISSION_BENCHMARK` | Scored long-horizon admission benchmark; statistics, not single anecdotal live retry |

---

## Diagnostics run for this report

| Command | Result |
|---------|--------|
| `git status --short` | ` M benchmark/reports/admissible_demo_readiness_post_slices.md` (pre-existing; not modified by this slice) |
| `python -m pytest tests/ -k admissible -q` | **834 passed**, 1258 deselected, 156 subtests passed |

---

## Files changed

| File | Change |
|------|--------|
| `benchmark/reports/admissible_cursor_live_batch_milestone_closure.md` | **added/updated** — this report |

No product code modified. **Committed:** no.
