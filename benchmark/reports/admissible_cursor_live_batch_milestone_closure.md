# Admissible — Cursor Live Batch Milestone Closure

**Slice:** `ADMISSIBLE_DEMO_020_CURSOR_LIVE_BATCH_MILESTONE_CLOSURE`  
**Date:** 2026-07-09  
**Mode:** documentation-only checkpoint (no provider calls, no shell/npm/git/deploy/network, no product changes, no commit)

---

## Milestone verdict

## **`CURSOR_LIVE_STRUCTURED_RUN_USABLE_WITH_BATCH_EXECUTION`**

A supervised, human-led Control Surface session can complete a live Cursor structured-response loop and apply admitted local file writes through explicit batch execution: **3 succeeded / 0 failed** for `index.html`, `style.css`, and `game.js`.

This is a **milestone**, not final proof. It demonstrates a bounded, supervised local side-effect loop with live agent output — not long-running autonomous task completion at the frontier of agent capability.

Related fix status: **`LIVE_BATCH_EXECUTION_CONTENT_GUARD_FIXED`** (slice 019 path-aware content guard; offline regression and live batch retry both pass 3/3).

---

## What was demonstrated

| Area | Evidence |
|------|----------|
| Goal-first Control Surface UX (014) | Blank session blocks instruction write until goal submitted; primary path is goal → bridge, not sample load |
| Sample demotion and safe load (015) | Examples collapsed; safe-load refuses non-empty sessions without `force` |
| Bridge/session binding (016) | `bridge-state.json` binds `session_id` and turn; stale/duplicate ingest blocked |
| Live structured-response ingest (017) | Cursor wrote only `.admissible/agent-response.md`; 3 `ADMISSIBLE_STRUCTURED_OPERATION` blocks extracted as admitted `create_file` actions; ingest did not auto-execute |
| Execution review UX (018) | Workspace persistence, ready-to-execute panel, explicit per-action and batch bounded-local execution |
| Content guard fix (019) | Path-aware `write_file` content policy; harmless goal-constraint prose in HTML/CSS no longer false-positives |
| Live batch execution (020 checkpoint) | Explicit batch execute after ingest: **3/3** files written with `bounded_executor` sha256 evidence |

**Flow in one sentence:** operator submits goal → writes bridge instruction → Cursor returns structured ops only → Admissible admits without executing → operator batch-executes admitted local writes → workspace contains the three scaffold files with evidence.

Prior reports: [admissible_cursor_live_structured_run_retry.md](./admissible_cursor_live_structured_run_retry.md) (017, per-file execute), [admissible_cursor_live_batch_content_guard_review.md](./admissible_cursor_live_batch_content_guard_review.md) (019 fix + offline 3/3 regression).

---

## What was not demonstrated

Do **not** infer any of the following from this milestone:

| Not claimed | Why |
|-------------|-----|
| Autonomous long-running task success | Single supervised turn; operator present at every gate and execute step |
| General software engineering autonomy | One narrow scaffold scenario (vanilla browser game files); no refactor, debug loop, or multi-feature delivery |
| Benchmark-level SOTA comparison | No paired frontier-direct vs Admissible-gated run; no scoring against a benchmark suite |
| Agent reliability solved | One successful live path; no adversarial extraction, no repeated-run statistics |
| Deployment readiness | No deploy, CI, packaging, or environment promotion |
| Production-grade UX | Known polish gaps (workspace picker, batch ergonomics, queue display) remain acceptable for demo, not product |

Also unchanged by this milestone:

- Admissible does not call providers; Cursor is external.
- Shell, npm, git, deploy, and network remain outside bounded-local execution unless future policy explicitly admits them.
- Admission rules were not weakened for this checkpoint.
- Multi-turn plan progress, evidence accumulation across turns, and blocked-action recovery in a live loop are not yet proven end-to-end.

---

## Why this still matters

Before slices 014–019, the canonical demo was **`DEMO_READY_WITH_SCRIPTED_LIMITS`**: coherent offline supervised loop over fixtures, with live Cursor and real side effects outside the readiness claim.

This milestone closes a specific gap: **live structured agent output → admission → human-approved bounded execution → verifiable local artifacts**, in one session, without ingest auto-execution and without weakening gates.

That is the minimum credible shape for “Admissible as a side-effect gate in front of a real agent” — even though it is only one turn and one scenario. It separates:

1. **Capability** (Cursor can propose structured local writes), from  
2. **Permission** (Admissible admits or blocks before any write), from  
3. **Execution** (bounded executor applies only explicitly invoked admitted ops).

The content-guard fix matters because a false positive on harmless constraint echo would have made the batch path look broken while the admission layer was correct — a product-trust failure distinct from gate logic.

---

## Current system status

| Layer | Status |
|-------|--------|
| Offline scripted supervised loop | **`DEMO_READY_WITH_SCRIPTED_LIMITS`** (slices 001–006; canonical e2e regression) |
| Live Cursor structured single-turn + batch execute | **`CURSOR_LIVE_STRUCTURED_RUN_USABLE_WITH_BATCH_EXECUTION`** (this milestone) |
| Batch content guard (HTML/CSS/JS prose vs real network refs) | **`LIVE_BATCH_EXECUTION_CONTENT_GUARD_FIXED`** |
| Multi-turn supervised/autonomy demo | **Not yet demonstrated** |
| Long-run autonomous completion | **Out of scope / not proven** |

**Tests (at closure time):** `python -m pytest tests/ -k admissible -q` → **834 passed**, 1258 deselected, 156 subtests passed.

**Working tree:** clean at report time.

---

## Remaining gaps before a “final” demo

1. **Multi-turn live loop** — second and subsequent turns with plan progress, stale-response protection across turns, and evidence carry-forward under live (not fixture) agent phrasing.
2. **Blocked-action handling in UI** — clear operator path when an action is `REFUSE`, needs evidence, or batch partial-failure; live recovery narrative not yet rehearsed.
3. **Plan gate closure across turns** — offline regression covers gates; live Cursor compliance with gate-resolution packets unproven.
4. **Evidence lane (G7)** — `reversibility` / `business_authority` unknown signals may still block otherwise-admitted ops; demo script may need explicit handling.
5. **UI polish** — `structured_operation_count`, queue `target_path` column, workspace picker, copy-Cursor-prompt shortcut (listed in 017 retry report).
6. **Repeated-run confidence** — single successful live batch; no flake or phrasing-drift statistics.
7. **Broader extraction** — adversarial or messy agent responses; mixed structured + natural-language turns.

None of these invalidate the milestone; they bound what the next demo narrative can honestly claim.

---

## Recommended next slices

**Primary direction:** move from single-turn structured local file proposal to a **bounded multi-turn supervised/autonomy demo**.

| Slice theme | Intent |
|-------------|--------|
| `ADMISSIBLE_DEMO_021_MULTI_TURN_STATE` | Persist turn counter, plan progress, and queue state across bridge ingest cycles in one session |
| `ADMISSIBLE_DEMO_022_PLAN_PROGRESS_UX` | Surface plan steps, completed vs pending, and next expected operator action in Control Surface |
| `ADMISSIBLE_DEMO_023_AGENT_PROPOSES_NEXT_STEP` | Instruction packet asks agent for next admitted op only; no shell/network/deploy unless future policy admits |
| `ADMISSIBLE_DEMO_024_LIVE_MULTI_TURN_REHEARSAL` | Human-led live Cursor rehearsal: 2–3 turns (e.g. scaffold → implement minimal game loop → verify locally) |
| `ADMISSIBLE_DEMO_025_BLOCKED_ACTION_RECOVERY` | Scripted live path when one op is refused or needs evidence; operator supplies evidence or skips without breaking session |
| `ADMISSIBLE_DEMO_026_EVIDENCE_ACCUMULATION_LIVE` | Cross-turn evidence records visible in Mission Summary; re-evaluation after supply |

**Policy boundary for next slices:** continue gating each side effect; no shell/network/deploy execution unless explicitly admitted by a future policy slice. Keep admission rules strict; extend orchestration and UX only.

**Secondary (polish, non-blocking):** queue display improvements from 017; optional workspace path persistence already partially addressed in 018 — verify across multi-turn.

---

## Diagnostics run for this report

| Command | Result |
|---------|--------|
| `git status` | clean working tree on `master` |
| `python -m pytest tests/ -k admissible -q` | **834 passed**, 1258 deselected, 156 subtests passed |

---

## Files changed

| File | Change |
|------|--------|
| `benchmark/reports/admissible_cursor_live_batch_milestone_closure.md` | **added** — this report |
| `benchmark/reports/admissible_demo_readiness_post_slices.md` | **updated** — narrow milestone pointer (section 12) |

No product code modified. **Committed:** no.
