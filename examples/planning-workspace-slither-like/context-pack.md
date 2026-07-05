---
plan_id: slither-like-example
artifact_type: CONTEXT_PACK
created_at: 2026-07-05T00:00:00Z
author: EXAMPLE_OWNER
version: 1
example_only: true
---

# Context Pack

> **Planning artifact type:** `CONTEXT_PACK`  
> **EXAMPLE_ONLY** — documentation sample; not used for real execution.

## Goal reference

**Goal ID / link:** `manifest.json` → `goal`

**Goal summary:** Build a small Slither-like browser game as static HTML/CSS/JS — single-page, no backend, playable in a modern browser.

## Source boundaries

| Source | Boundary | Notes |
|--------|----------|-------|
| Target project repo | read-only | Hypothetical greenfield `slither-demo/` |
| Agent OS templates | read-only | Planning layout reference only |
| Prior runs | excluded | No prior execution for this example |

## Files inspected

```
(hypothetical — none in this EXAMPLE_ONLY pack)
```

## Files explicitly not inspected

```
.agent-os/runs/
dist/
node_modules/
```

## Constraints discovered

- Static assets only — no build toolchain required for v1
- Canvas 2D API sufficient for snake rendering
- Must run from `file://` or simple static server

## Existing project state

Greenfield example. No open runs, no prior closure verdicts.

## Unknowns / open questions

| # | Question | Impact if unresolved | Suggested owner action |
|---|----------|----------------------|------------------------|
| 1 | Keyboard vs touch controls? | Affects slice 4 scope | Owner decides in spec |
| 2 | Target viewport size? | Layout polish | Default 800×600 in spec |

## Risks

| Risk | Likelihood | Impact | Mitigation (planning only) |
|------|------------|--------|---------------------------|
| Scope creep into multiplayer | medium | Plan bloat | Non-goals in Local Agentic Spec |
| Game loop timing bugs | medium | Poor UX | Dedicated canvas-loop slice |

## Assumptions

- Owner accepts browser-only delivery
- No package manager required for the demo

## Evidence / provenance

| Claim | Source | Captured at |
|-------|--------|-------------|
| Layout contract | `docs/planning-workspace-layout.md` | 2026-07-05 |

---

## Non-authority statement

**This artifact collects context. It does not define scope, approve work, execute code, audit execution, or close a run.**
