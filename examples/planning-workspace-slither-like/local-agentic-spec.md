---
plan_id: slither-like-example
artifact_type: LOCAL_AGENTIC_SPEC
created_at: 2026-07-05T00:00:00Z
author: EXAMPLE_OWNER
version: 1
status: DRAFT
example_only: true
---

# Local Agentic Spec

> **Planning artifact type:** `LOCAL_AGENTIC_SPEC`  
> **EXAMPLE_ONLY** — documentation sample; owner acceptance not recorded.

## Goal summary

Deliver a playable single-player Slither-like game in static HTML/CSS/JS: snake grows by eating food, dies on wall or self-collision, score displayed, restart available.

## In-scope outcomes

- Canvas-based game with requestAnimationFrame loop
- Arrow-key steering (keyboard)
- Food spawn, score increment, collision detection
- Game-over screen with restart
- README with how to open the game locally

## Out-of-scope outcomes

- Multiplayer or networking
- Backend, databases, or auth
- Mobile touch controls (deferred)
- Asset pipelines (webpack, bundlers)

## User-visible success criteria

| Criterion | Observable signal | Owner-verifiable |
|-----------|-------------------|------------------|
| Playable snake | Snake moves and responds to keys | yes |
| Score works | Score increases when food eaten | yes |
| Death + restart | Collision ends run; restart works | yes |
| Static delivery | Open `index.html` in browser | yes |

## Non-goals

- Production deployment or hosting
- Automated CI for the game repo
- Pixel-art assets or sound

## Constraints

| Constraint | Value | Rationale |
|------------|-------|-----------|
| Technology | HTML5, CSS, vanilla JS | Static, no build step |
| Files | Under `slither-demo/` in target project | Bounded tree |
| Planning writes | Read-only on target repo until execution approved | Doctrine |

## Allowed technology / forbidden technology

**Allowed:** HTML5 Canvas, CSS, ECMAScript (browser), `requestAnimationFrame`.

**Forbidden:** Node servers, WebSockets, React/Vue (unnecessary for v1), localStorage persistence (optional polish only).

## Quality bar

- Readable source structure (`game.js`, `index.html`, `style.css`)
- No global namespace pollution beyond one `Game` object
- Manual playtest checklist in execution evidence

## Ambiguities requiring owner decision

| # | Ambiguity | Options | Owner decision |
|---|-----------|---------|----------------|
| 1 | Canvas size | 640×480 vs 800×600 | PENDING — suggest 800×600 |
| 2 | Snake speed curve | Fixed vs accelerating | PENDING — suggest fixed for v1 |

## Drift risks

| Drift risk | Early signal | Guardrail |
|------------|--------------|-----------|
| Spec treated as run mission | Agent edits repo during planning | Local Agentic Spec forbids execution |
| Plan slice run without proposal | Direct `invoke-run` | Implementation Plan cites proposal gate |

---

## Non-authority statement

**This artifact specifies local intent. It does not execute, audit, approve, or close work.**
