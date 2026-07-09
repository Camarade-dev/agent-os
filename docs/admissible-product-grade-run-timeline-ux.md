# Admissible product-grade run timeline UX (slice ADMISSIBLE_UX_026)

## What this slice changes

The Control Surface already had the right underlying governed-run mechanics:
multi-turn timeline, evidence-grounded continuation, blocker/recovery state,
and explicit bounded local verification. This slice improves **how that story
is presented** so a demo viewer can understand the run quickly without reading
raw queue JSON or bridge internals.

### Governed Run overview (new top panel)

A single **Governed Run** panel summarizes:

- goal
- run phase / status
- turn count
- ready-to-execute count
- blocked / refused count
- write evidence count
- verification readiness (not run / pass / fail)
- whether evidence-grounded continuation is available

This is a derived `governed_run_overview` field on `state_view()` — not persisted,
not authoritative.

### Run Timeline (improved)

Each turn is shown as a card with a compact table per proposed operation:

| Proposal | Admission | Execution | Evidence | Blocked |
|----------|-----------|-----------|----------|---------|

Aggregate stats moved to **Governed Run**; the timeline focuses on the per-turn
sequence: what the agent proposed, what Admissible admitted, what was executed,
what write evidence exists, and what remains blocked / not completed.

### Evidence-Grounded Continuation (clearer)

The continuation panel now states explicitly:

- **Unavailable** when admitted local file operations are still pending execution
- **Available** after execution evidence exists
- blocked/refused actions listed as **not completed** (must not be treated as done)
- the copyable instruction is the **next safe human-driven step**
- continuation **does not mean auto-execution** (no provider calls, no executor)

### Bounded Verification (new panel)

Exposes verification state from `verification_summary`:

- not run / pass / fail
- latest profile
- passed and failed check counts
- failed check messages when present
- explicit **Run bounded verification** button →
  `POST /api/queue/verify_bounded_local_workspace`

Verification never auto-runs on page load or after ingest/execution.

### Secondary / debug surfaces

Moved to collapsible **Advanced** drawers:

- Mission Summary (aggregate decision counts)
- Session diagnostics & bridge internals
- Session transcript

The supervised Cursor bridge and admission queue remain available for operators
who need them; the narrative panels lead the demo story.

## How this supports the final demo

The canonical four-turn local build + blocker/recovery rehearsal now reads as:

1. **Governed Run** — goal and phase at a glance
2. **Run Timeline** — Turn 1 scaffold → batch execution → evidence → Turn 2 …
3. **Continuation** — blocked until execution; then copyable next instruction
4. **Bounded Verification** — operator clicks verify after recovery writes

A viewer can follow: *what we want → what happened each turn → what was blocked →
what evidence exists → whether checks passed → what to do next* without treating
the UI as a lab console.

## What remains non-product-grade

- No polished SaaS visual design; dark dev harness styling only
- Bridge workspace path entry is still manual
- Queue table, selected action, goal intake, and plan audit are unchanged and
  still technical
- Mission summary and diagnostics are available but tucked under Advanced
- No live Cursor API integration; file bridge + copy/paste fallback only
- No completion model; continuation always asks for the next smallest step

## Why no new authority or execution powers were added

This slice is **display-only** plus one explicit human-triggered button that
calls an **existing** route (`verify_bounded_local_workspace`). It does not:

- call providers
- auto-execute admitted operations or verification
- broaden bounded executor capabilities
- weaken content guards or change admission policy
- add shell/npm/deploy/network automation

All new fields (`governed_run_overview`, enriched `verification_summary`) are
projections over session state already computed by `build_run_timeline`,
`build_continuation_instruction`, and stored `verification_records`.

## Tests

`tests/test_admissible_product_grade_run_timeline_ux.py` asserts:

- HTML markers for Governed Run, Run Timeline, Continuation, Bounded Verification
- `state_view()` exposes `governed_run_overview` and `verification_summary`
- verification button route identifier present; no auto-run on page load
- overview fields are not persisted in `session_dict()`

Existing timeline, continuation, verification, and demo tests should continue
to pass unchanged.
