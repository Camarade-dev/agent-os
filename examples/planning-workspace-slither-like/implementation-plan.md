---
plan_id: slither-like-example
artifact_type: IMPLEMENTATION_PLAN
created_at: 2026-07-05T00:00:00Z
author: EXAMPLE_OWNER
version: 1
status: DRAFT
spec_ref: local-agentic-spec.md
example_only: true
---

# Implementation Plan

> **Planning artifact type:** `IMPLEMENTATION_PLAN`  
> **EXAMPLE_ONLY** — planned slices are not executable until converted to Next Run Proposals and approved.

## Spec reference

**Local Agentic Spec:** `local-agentic-spec.md` (version 1, EXAMPLE_ONLY)

**Spec version:** 1

## Plan summary

Eight ordered slices take a greenfield static project from spec confirmation through scaffold, core loop, gameplay, polish, and README closure. Each slice is one bounded execution run when proposed via the experimental runner.

## Ordered slices / runs

| Order | Run label | Mission (summary) | Authority | Dependencies |
|-------|-----------|---------------------|-----------|--------------|
| 1 | slice-01-spec-confirmation | Confirm spec ambiguities resolved | L1 | — |
| 2 | slice-02-scaffold | Create HTML/CSS/JS scaffold | L2 | slice-01 |
| 3 | slice-03-canvas-loop | Canvas + game loop | L2 | slice-02 |
| 4 | slice-04-snake-movement | Snake segment movement and input | L2 | slice-03 |
| 5 | slice-05-food-score | Food spawn and score | L2 | slice-04 |
| 6 | slice-06-collision-restart | Collision detection and restart | L2 | slice-05 |
| 7 | slice-07-polish | UI polish and constants | L2 | slice-06 |
| 8 | slice-08-readme-closure | README and playtest evidence | L1 | slice-07 |

---

## Planned run: slice-01-spec-confirmation

**Run label:** `slice-01-spec-confirmation`

**Mission:** Resolve owner decisions on canvas size and snake speed; update spec section only if owner approves.

**Scope:** Edit `local-agentic-spec.md` ambiguities table in planning workspace only. No game code.

**allowed_paths:**

```json
[
  ".agent-os/planning/slither-like-example/local-agentic-spec.md",
  ".agent-os/planning/slither-like-example/decisions/"
]
```

**authority:** L1

**expected evidence:** Owner decision record in `decisions/`; updated ambiguity rows.

**check_command:** (none)

**stop conditions:** Stop if owner declines to decide; escalate to BLOCKED status.

**owner gates:** `planning-owner-decision-required` before slice-02 proposal.

**dependencies:** Accepted Context Pack and draft spec.

---

## Planned run: slice-02-scaffold

**Run label:** `slice-02-scaffold`

**Mission:** Create minimal `slither-demo/` with `index.html`, `style.css`, `game.js` stubs.

**Scope:** Scaffold files only; no game logic beyond placeholders.

**allowed_paths:**

```json
[
  "slither-demo/index.html",
  "slither-demo/style.css",
  "slither-demo/game.js"
]
```

**authority:** L2

**expected evidence:** Three files exist; browser opens blank canvas container.

**check_command:** (none)

**stop conditions:** Do not implement loop or snake in this slice.

**owner gates:** Next Run Proposal approval per runner doctrine.

**dependencies:** slice-01-spec-confirmation

### Structured slice contract (EXAMPLE_ONLY — `slice-001-scaffold`)

> **EXAMPLE_ONLY** — canonical machine-readable contract for the scaffold slice.  
> `slice_id` `slice-001-scaffold` is the demo id used in runner planning-reference tests.  
> This block does not create runs, approve proposals, or invoke executors.  
> Structured runner import is **not implemented**; see `docs/planning-structured-slice-format.md`.

```json
{
  "artifact_type": "PLANNING_RUN_SLICE",
  "schema_version": "0.1",
  "slice_id": "slice-001-scaffold",
  "mission": "Create minimal slither-demo/ with index.html, style.css, game.js stubs.",
  "scope": "Scaffold files only; no game logic beyond placeholders.",
  "authority": "L2",
  "allowed_paths": [
    "slither-demo/index.html",
    "slither-demo/style.css",
    "slither-demo/game.js"
  ],
  "check_command": "",
  "expected_evidence": [
    "Three files exist; browser opens blank canvas container."
  ],
  "stop_conditions": [
    "Do not implement loop or snake in this slice."
  ],
  "owner_gates": [
    "Next Run Proposal approval per runner doctrine."
  ],
  "dependencies": [
    "slice-01-spec-confirmation"
  ],
  "non_authority": {
    "does_not_create_run": true,
    "does_not_approve_proposal": true,
    "does_not_invoke_executor": true,
    "requires_runner_proposal": true,
    "requires_approve_next_run": true,
    "requires_invoke_run_allow_executor": true
  }
}
```

---

## Planned run: slice-03-canvas-loop

**Run label:** `slice-03-canvas-loop`

**Mission:** Wire canvas element and `requestAnimationFrame` clear/draw stub.

**Scope:** Loop and clear only; no snake entity yet.

**allowed_paths:**

```json
[
  "slither-demo/game.js",
  "slither-demo/index.html"
]
```

**authority:** L2

**expected evidence:** Console or visual proof of steady loop; no errors in browser console.

**check_command:** (none — manual browser check)

**stop conditions:** Stop if canvas dimensions conflict with spec decisions.

**owner gates:** Proposal approval.

**dependencies:** slice-02-scaffold

---

## Planned run: slice-04-snake-movement

**Run label:** `slice-04-snake-movement`

**Mission:** Implement snake segments, direction queue, and keyboard input.

**Scope:** Movement and rendering snake body; no food or score.

**allowed_paths:**

```json
[
  "slither-demo/game.js"
]
```

**authority:** L2

**expected evidence:** Snake moves on arrow keys; wraps or stops per spec (wall behavior documented).

**check_command:** (none)

**stop conditions:** Do not add food or collision beyond self-check stub.

**owner gates:** Proposal approval.

**dependencies:** slice-03-canvas-loop

---

## Planned run: slice-05-food-score

**Run label:** `slice-05-food-score`

**Mission:** Spawn food at valid cells; increment score on eat; grow snake.

**Scope:** Food and score only; collision death deferred to next slice.

**allowed_paths:**

```json
[
  "slither-demo/game.js",
  "slither-demo/index.html"
]
```

**authority:** L2

**expected evidence:** Score updates when food eaten; snake length increases.

**check_command:** (none)

**stop conditions:** Stop if food spawns inside snake repeatedly — fix spawn logic only.

**owner gates:** Proposal approval.

**dependencies:** slice-04-snake-movement

---

## Planned run: slice-06-collision-restart

**Run label:** `slice-06-collision-restart`

**Mission:** Wall and self-collision game-over; restart button or key.

**Scope:** Collision, game state machine, restart — no polish.

**allowed_paths:**

```json
[
  "slither-demo/game.js",
  "slither-demo/index.html",
  "slither-demo/style.css"
]
```

**authority:** L2

**expected evidence:** Game ends on collision; restart returns to playable state.

**check_command:** (none)

**stop conditions:** Full playable loop must work before polish slice.

**owner gates:** Proposal approval.

**dependencies:** slice-05-food-score

---

## Planned run: slice-07-polish

**Run label:** `slice-07-polish`

**Mission:** Improve layout, colors, score display, and game-over overlay.

**Scope:** CSS and minor JS presentation only; no new mechanics.

**allowed_paths:**

```json
[
  "slither-demo/style.css",
  "slither-demo/index.html",
  "slither-demo/game.js"
]
```

**authority:** L2

**expected evidence:** Readable score and game-over UI; owner playtest note.

**check_command:** (none)

**stop conditions:** No new features (sound, levels).

**owner gates:** Proposal approval.

**dependencies:** slice-06-collision-restart

---

## Planned run: slice-08-readme-closure

**Run label:** `slice-08-readme-closure`

**Mission:** Add `slither-demo/README.md` with open instructions and manual test checklist.

**Scope:** Documentation and evidence registration only.

**allowed_paths:**

```json
[
  "slither-demo/README.md"
]
```

**authority:** L1

**expected evidence:** README complete; execution evidence references manual playtest.

**check_command:** (none)

**stop conditions:** Planning package may move to CLOSED after owner accepts final run.

**owner gates:** Final owner decision on program goal; planning closure.

**dependencies:** slice-07-polish

---

## Plan revision policy

Revisions stored under `revisions/`; `active_revision` in manifest updated only after owner approval.

| Version | Date | Author | Change summary | Owner approval |
|---------|------|--------|----------------|----------------|
| 1 | 2026-07-05 | EXAMPLE_OWNER | Initial EXAMPLE_ONLY plan | PENDING |

## Plan-to-run boundary

**A planned run is not executable until converted into a next-run proposal and approved.**

Mapping to execution is manual via experimental runner (`propose-next-run` → `approve-next-run` → separate `invoke-run --allow-executor`). This EXAMPLE_ONLY plan must not be imported automatically.

---

## Non-authority statement

**This artifact proposes decomposition. It does not create runs, invoke executors, audit work, or approve continuation.**
