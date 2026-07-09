# Admissible Product / UX / Generalization Audit

**Slice:** `ADMISSIBLE_AUDIT_013_PRODUCT_UX_GENERALIZATION_AND_LIVE_RUN_FLOW`
**Date:** 2026-07-09
**Scope:** Admissible Control Surface (browser UI + HTTP bridge + controller) from a blank session to a live local dynamic run.
**Method:** full code read of `admissible/control_surface.py`, `admissible/runner/control_surface.py`, `admissible/runner/cursor_bridge.py`, `admissible/run_loop.py`, `admissible/goal_intake.py`, `admissible/execution/bounded_local_executor.py`, and `admissible/harness/control_surface.html`; in-process behavioral probes (no server, no provider, no shell); full diagnostic test run. No shell/npm/git/deploy/network execution beyond running pytest and the in-process probes.

---

## 1. Executive verdict

## **`TECH_READY_UX_NOT_READY`**

The engine is demonstrably solid: 771 admissible tests pass (plus 7 intentional xfails added by this audit), the canonical offline e2e regression passes, the bounded executor is properly gated, ingest is verified side-effect-free, and the live Cursor bridge rehearsal passes. Nothing found in this audit weakens a gate or touches a decision path.

But the product experience from a blank prompt is not demo-ready. The blank-session page leads with **Session Diagnostics** (a debug panel), then the **Cursor supervised file bridge**, and buries the goal form as the **10th section** on the page. A user can click "Write instruction file" before any goal exists; Admissible then writes a real instruction file into the workspace whose TASK section reads *"No goal has been submitted to Admissible yet."*, advances the turn counter, and permanently marks that turn as "awaiting Cursor response" — an impossible state the UI then displays as truth for the rest of the session. The single primary-styled button in the header is "Load sample Slither session", which silently destroys any in-progress session with no confirmation.

All of these were reproduced empirically (section 4). None of them require engine changes to fix — they are ordering, guarding, and copy problems, which is why the verdict is TECH_READY_UX_NOT_READY rather than a NOT_READY variant. However, the first-run-flow bugs (GAP-001/002/003) are hard blockers for a clean live demo from a blank prompt: expect the verdict to be effectively `NOT_READY_FIRST_RUN_FLOW_GAPS` for a demo scheduled before slice UX-A lands.

## 2. Current readiness status

| Area | Status |
|---|---|
| Offline canonical e2e regression | ✅ passing |
| Structured evidence packets | ✅ passing |
| No-envelope evidence projection | ✅ passing |
| Bounded local executor v0 (gating, workspace jail, forbidden ops) | ✅ passing |
| Structured operation proposal contract | ✅ passing |
| Tiny local game dynamic run (fixture) | ✅ passing |
| Control Surface HTTP bridge rehearsal | ✅ passing |
| Ingest side-effect freedom | ✅ verified by probe + new guard test |
| Blank-session first-run flow | ❌ P0 gaps (no-goal instruction, buried goal form) |
| Generalization beyond Slither | ⚠️ engine generalizes; UI copy/defaults do not |
| Information architecture | ❌ debug-first ordering, no visibility hierarchy |
| State machine / UI consistency | ⚠️ orphaned awaiting-turns, cross-session ingest after reset, unguarded sample load |
| Product language | ⚠️ lab-grade, repetitive safety copy, internal jargon exposed |

## 3. What is technically solid now

- **Decision integrity.** Original rules-only decisions are never mutated; superseding decisions, human decisions, and lifecycle resolutions are all separate append-only records. `available_human_actions()` is the single autonomy/decision meeting point and is well tested.
- **Bounded executor.** Requires admission, validates workspace containment, refuses forbidden operation categories via both token and natural-language pattern checks, and emits verifiable execution records + evidence.
- **Bridge verifiability.** Every file write/read returns re-derived path/bytes/sha256/mtime; stale and duplicate responses are blocked with typed, machine-readable errors; blocked ingests are recorded in the transcript without creating queue items.
- **Goal intake generalization.** `analyze_goal()` is a task-agnostic keyword classifier (build/bugfix/refactor/explain; risk/complexity/side-effect classes). Arbitrary local tasks flow through it — the tiny-local-game dynamic run proves the non-Slither path end to end.
- **Session persistence.** Every mutation persists; corrupt session files fail loudly (`InvalidSessionFileError`) instead of silently resetting.

## 4. Why the live blank-prompt UX is not ready — probe results

In-process probes (fresh controller + scratch workspace, no server):

| Probe | Result | Observed |
|---|---|---|
| P1 Generate instruction, no goal | **BUG** | Succeeds; packet task = `"No goal has been submitted to Admissible yet."`; turn advances to 1 |
| P2 Bridge "Write instruction file", no goal | **BUG** | Writes the no-goal packet to `<ws>/.admissible/next-agent-instruction.md`; `bridge-state.json` sets `awaiting_response: true`; diagnostics show "awaiting Cursor response" with no goal |
| P3 Orphaned awaiting turn | **BUG** | After a goal is submitted and turn 2 completes a full round trip, turn 1 (the no-goal packet) remains in `bridge_awaiting_turns` forever — diagnostics permanently claim an outstanding response |
| P4 Manual paste ingest, no goal | **BUG** | Succeeds with no goal and no instruction; queue item created at turn 0 |
| P5 "Load sample Slither session" | **BUG** | Silently replaces an in-progress session (new session id, Slither goal) — no confirmation; the UI's Reset button *does* confirm, the more destructive sample button does not |
| P6 Reset, then ingest pre-reset response | **BUG** | A response file written for the *previous* session's instruction ingests cleanly into the fresh session: `bridge-state.json` stores `session_id` but `_validate_response_for_ingest` never checks it, and `session_turn=0` is falsy so the turn-mismatch guard is skipped |
| P7 Ingest side effects | OK | No files created outside `.admissible/` |
| P8 Blank state_view | INFO | UI's first rendered panel is diagnostics (session file path, disk-load status, turn, awaiting flag) |

**Manual observation summary (matches the reported rehearsal):** on load, the user sees a dark lab console: version-numbered title, four warning pills, a sticky control bar whose only primary button is the Slither sample, a diagnostics table, then a four-step bridge whose buttons are all enabled before any goal exists. The "Send a Goal" form — the actual entry point of the whole product — is below the fold under six other panels. The empty mission summary does say "Send a goal below", pointing the user *away* from the visible controls toward a form they must scroll to find.

## 5. Gap table

| ID | Sev | Category | Observed | Expected |
|---|---|---|---|---|
| GAP-001 | P0 | first-run-flow | "Write instruction file" / "Generate next agent instruction" work with no goal; packet TASK = "No goal has been submitted to Admissible yet."; turn advances; `awaiting_response` set | Both paths rejected with a clear "submit a goal first" error; UI disables the buttons with an inline explanation; turn counter untouched |
| GAP-002 | P0 | first-run-flow / IA | Goal form is the 10th panel; page leads with diagnostics + bridge | Goal input is the first and visually dominant element of a blank session; bridge/workspace/instruction controls hidden or disabled until a goal exists |
| GAP-003 | P0 | generalization | "Load sample Slither session" is the only primary-styled header button; empty state and goal placeholder mention Slither; `load_sample_session()` silently wipes the session | Sample demoted to a secondary "Load a sample run" affordance (sample gallery / advanced drawer), generic naming, confirmation (or auto-archive) before replacing a non-empty session |
| GAP-004 | P1 | state-machine | Orphaned `bridge_awaiting_turns` entries persist forever; diagnostics permanently show "awaiting response" | Superseded instruction turns marked `superseded_by_turn_N` and excluded from the awaiting list |
| GAP-005 | P1 | state-machine | After reset, a pre-reset response file ingests into the fresh session (bridge-state `session_id` never validated; `session_turn=0` falsy skips turn check) | Ingest validation compares `bridge_state.session_id` to the live session and rejects on mismatch; explicit `session_turn == 0` handling |
| GAP-006 | P1 | first-run-flow | Manual paste ingest accepts responses with no goal/instruction at turn 0 | Ingest requires a goal (and ideally an outstanding instruction) or is explicitly labeled as a debug-only import |
| GAP-007 | P1 | IA | Diagnostics, truth boundary, autonomy details, bridge raw file facts (sha256/bytes/mtime), raw packet preview all visible by default | Single collapsed "Advanced / Debug" drawer; default view shows only the 7-level product hierarchy (section 6) |
| GAP-008 | P2 | product-language | Lab phrasing throughout: "Admissible Control Surface v0", "Mission Summary", "Admissible Action Admission Queue", "Ingest Cursor response file", "Attest executed after admission", triple-repeated non-execution disclaimers | Product-grade names (section 8) and one calm, persistent safety line instead of three warning banners |
| GAP-009 | P2 | IA / trust | Mission summary shows a 15-tile stat grid incl. `side_effect_executed_by_admissible: false` as raw text | 3–4 headline tiles (needs-you-now, admitted, executed, blocked); the rest in the queue view or drawer |
| GAP-010 | P2 | architecture | 1,617-line monolithic HTML file: CSS + 14 panels + all JS in one file; render() re-renders everything | Split templates/modules (section 9); add missing state_view fields (`has_goal`, `next_expected_action`, superseded turns) so the UI stops deriving product state client-side |

## 6. Proposed product information architecture

Default view, top to bottom (matches the requested hierarchy):

1. **Goal / Run objective** — one prominent input on blank sessions; once submitted, a compact header: goal text, task type, risk, autonomy level.
2. **Current step** — a single stepper: `Goal → Plan review → Workspace → Instruction sent → Awaiting agent → Review actions → Execute admitted → Done`, with exactly one "what to do next" line.
3. **Agent instruction / response status** — turn number, instruction written (path, one-line), awaiting/ingested state. File facts (sha256, bytes, mtime) behind a "details" toggle.
4. **Decisions needed** — today's "pending human decision" bucket only; each row has its decision controls inline (merge Selected Action into the row expansion).
5. **Admitted local actions** — admitted-not-executed items with the bounded-execute affordance (only when eligible) or attest affordance.
6. **Execution / evidence** — executed items with their verifiable execution records and evidence trail.
7. **Trace / debug drawer (collapsed)** — session diagnostics, truth boundary long text, transcript, decision history (full), raw packet preview, bridge raw details, autonomy profile details, import/export, sample gallery, load-trace.

Panel disposition of every existing element:

| Element | Today | Proposed |
|---|---|---|
| Session diagnostics | First panel, always open | Debug drawer |
| Truth boundary | Header `<details>` + banner + footer (3×) | One calm line under header; full text in drawer |
| Autonomy level | Sticky top bar | Goal header chip; selector in a "Run settings" popover |
| Bridge raw details (sha/bytes/mtime) | Inline in step status | "details" toggle per step |
| Mission summary | 15-tile grid | 3–4 headline tiles in goal header |
| Supervised run state buckets | Always visible, 6 buckets incl. empty ones | "Decisions needed" (bucket 1) + "Closed" collapsible; empty buckets hidden |
| Action queue table | Always visible, 4 tabs | Merged with Decisions needed / Admitted / Executed sections; "All actions" table in drawer |
| Selected action | Separate panel below queue | Inline row expansion |
| Goal intake / plan audit | Two separate panels | One "Plan review" step card; full detail in drawer |
| Decision history | Panel + nested details | Debug drawer |
| Transcript | Footer details | Debug drawer |
| Raw instruction packet preview | Manual-fallback textarea | Drawer (debug) |
| SHA/file metadata | Inline everywhere | Behind toggles |

## 7. Proposed first-run flow

Blank session renders exactly:

1. Product title + one-line calm boundary statement ("Admissible reviews and admits agent actions. It never executes shell commands or calls a provider.")
2. **Goal input** (large, focused, generic placeholder: "Describe what you want built or changed in a local workspace…") + submit button.
3. A muted "or explore a sample run" link (opens sample gallery in the drawer).

After goal submit: plan review card appears (verdict + gates + clarifying questions), then the workspace step unlocks, then "Send instructions to your agent" (bridge write) unlocks — in that order, each step disabled-with-reason until its predecessor is done. `state_view` gains `has_goal` and `next_expected_action` so the UI never re-derives this client-side. Server-side, `generate_next_instruction_packet()` and `write_next_instruction_with_controller()` raise `ValueError("submit a goal before generating an instruction packet")` when `goal_intake is None` (GAP-001) — the packet's "No goal" fallback string becomes unreachable and is deleted.

## 8. Proposed UI copy changes

| Current | Proposed |
|---|---|
| Admissible Control Surface v0 | **Admissible** (subtitle: "Supervised agent runs") |
| Mission Summary | **Run overview** |
| Supervised Run State | **Decisions needed** (+ "Closed items" collapsible) |
| Admissible Action Admission Queue | **Proposed actions** |
| Cursor supervised file bridge | **Agent handoff** (works for any file-bridge agent, not only Cursor) |
| Load sample Slither session | **Load a sample run** (in sample gallery/drawer) |
| Write instruction file | **Send instructions to agent** |
| Ingest Cursor response file | **Check for agent response** |
| Execute bounded local file action | **Apply approved file changes** (subtext: "local files only — no shell, no install, no network") |
| Attest executed after admission | **Mark as done outside Admissible** |
| "This is the canonical way to run a turn with Cursor…" (5-line paragraph) | "1. Admissible writes instructions to a file. 2. Your agent reads it and writes a reply. 3. Admissible reviews the reply." |
| Three stacked non-execution banners | One persistent footer line; full boundary text in drawer |

Keep visible but calmer: the safety boundary should be one short, always-present line ("Admissible never executes shell commands, installs packages, or calls the network — file changes happen only after your approval") rather than three warning-colored banners. Autonomy-level fine print, provider name lists, and "v0" qualifiers move to the drawer/docs.

## 9. Technical architecture for the UI refactor

**Safe to refactor freely (display-only):** everything in `control_surface.html` — all `render*()` functions are pure projections of `state_view()`; no decision logic lives client-side except button-enable heuristics (which should come from the server anyway). `_mission_summary`, `_needs_attention`, `_lifecycle_overview`, `_session_diagnostics` in `control_surface.py` are explicitly display-only aggregates and can be reshaped without touching gates.

**Must not change:** `available_human_actions()`, `decide()`, `provide_evidence()`, `execute_bounded_local()`, `validate_executed_after_admission_record` usage, ingest validation, and the append-only decision records.

**Missing `state_view` fields for a polished UI:**
- `has_goal: bool` and `next_expected_action: str` (drives the stepper and button gating);
- `run_phase`: one of `awaiting_goal | plan_review | ready_to_instruct | awaiting_agent_response | reviewing_actions | executing_admitted | idle_complete`;
- superseded/awaiting turn reconciliation (fix GAP-004) so `bridge_awaiting_turns` is truthful;
- per-item `blocked_reason` strings for disabled affordances ("Needs approval before execution", "Workspace not set");
- sample metadata (`is_sample_session: bool`) so sample runs are visibly labeled.

**Monolith:** 1,617 lines mixing CSS (~230), HTML (~220), and JS (~1,150) in one file; `render(state)` re-renders 12 panels on every action. Recommendation: **keep the stdlib server and no-build constraint** (it is a real deployment asset for a local-only tool), but split into `control_surface.css`, `control_surface.js` (ES modules: `api.js`, `render/*.js`), and a template HTML, served by the same handler (3 more static routes). Do not introduce a frontend framework/build step in the next slice; revisit only if interactivity outgrows this (e.g. optimistic updates, routing).

## 10. Proposed implementation slices

1. **`ADMISSIBLE_UX_014_GOAL_FIRST_GATING`** (P0, small) — server-side goal guards on packet generation + bridge write + (debug-labeled) paste ingest; add `has_goal`/`run_phase`/`next_expected_action` to `state_view`; UI disables instruction/bridge buttons with reasons; goal panel moved to top; flips 3 xfail tests in `tests/test_admissible_first_run_product_gaps.py`.
2. **`ADMISSIBLE_UX_015_SAMPLE_DEMOTION_AND_GENERIC_COPY`** (P0, small) — demote/rename sample loader, confirmation before replacing a non-empty session, generic goal placeholder, remove Slither from default-path copy; flips the remaining xfails.
3. **`ADMISSIBLE_STATE_016_BRIDGE_SESSION_BINDING`** (P1, small) — validate `bridge_state.session_id` on ingest; explicit turn-0 handling; mark superseded instruction turns; truthful `bridge_awaiting_turns`.
4. **`ADMISSIBLE_UX_017_IA_RESTRUCTURE`** (P1, medium) — implement the 7-level hierarchy: stepper, merged decisions/queue/selected-action, debug drawer; split HTML/CSS/JS files; copy changes from section 8.
5. **`ADMISSIBLE_UX_018_LIVE_RUN_POLISH`** (P2, medium) — agent-handoff step cards with per-step "what Cursor should do now" text, blocked-state explanations with next action, bounded-execute affordance polish, closed/pending separation everywhere.

## 11. Proposed tests (beyond those added)

- Goal guard: bridge write with no goal leaves workspace untouched **and** turn counter at 0 (added, xfail → flip in slice 014).
- `run_phase` state machine: blank → `awaiting_goal`; after goal → `plan_review`/`ready_to_instruct`; after write → `awaiting_agent_response`; after ingest → `reviewing_actions` (slice 014).
- Sample loader: refuses (or archives) when the current session has a goal/queue; sample sessions carry `is_sample_session: true` (slice 015).
- Bridge/session binding: response written under session A rejected after reset to session B (slice 016; probe P6 is the repro).
- Awaiting-turn truthfulness: superseded turn absent from `bridge_awaiting_turns` (slice 016; probe P3 is the repro).
- HTML IA guards: goal panel first; diagnostics inside collapsed details; exactly one always-visible safety banner (slice 017 flips the xfails already written).
- Live path guard: rehearsal test (`test_admissible_control_surface_live_dynamic_run_rehearsal.py`) must keep passing unchanged through every slice.

## 12. Tests added by this audit

`tests/test_admissible_first_run_product_gaps.py` — 10 tests: 7 `@unittest.expectedFailure` desired-behavior tests (P0 documentation; suite stays green; a fix produces an unexpected-success signal so the decorator is removed with the fix) and 3 passing refactor guards (ingest writes nothing outside `.admissible/`; bounded execution still requires admission; `side_effect_executed_by_admissible` stays false).

Full diagnostic results (2026-07-09):

| Command | Result |
|---|---|
| `pytest tests/ -k admissible -q` | 771 passed, 7 xfailed, 156 subtests passed |
| `pytest tests/test_admissible_canonical_demo_e2e.py -q` | passed |
| `pytest tests/test_admissible_bounded_local_executor.py -q` | passed |
| `pytest tests/test_admissible_structured_operation_contract.py -q` | passed |
| `pytest tests/test_admissible_tiny_local_game_dynamic_run.py -q` | passed |
| `pytest tests/test_admissible_control_surface_live_dynamic_run_rehearsal.py -q` | passed |

Nothing was committed. No gate, decision path, or executor capability was modified.
