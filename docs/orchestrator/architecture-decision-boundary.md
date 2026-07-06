# Architecture decision boundary

> **Status:** doctrine and contract only — no orchestrator, no auto-selection, no execution  
> **Slice:** `CORE_ORCHESTRATOR_001`  
> **Companion:** [`goal-to-planning-workspace-contract.md`](goal-to-planning-workspace-contract.md)

This document defines how a future Agent OS orchestrator must represent **architecture and infrastructure choices** between goal intake and planning workspace drafting. The orchestrator may **propose** options; it must not **decide** invisibly. **architecture recommendation is not owner decision.**

---

## 1. Why architecture must be explicit

The goal-to-planning layer makes decisions that are expensive to change later:

- Frontend/runtime and game loop model
- Networking and state synchronization
- Backend/runtime and persistence
- Deployment and environment assumptions
- First implementation slice boundary

Silent defaults embedded in generated Markdown destroy auditability. Every choice must be traceable: options considered, option selected (as recommendation), rationale, reversibility, and unknowns requiring owner validation.

---

## 2. Architecture Decision Record (ADR) contract

A future orchestrator emits an **Architecture Decision Record** as structured data (JSON or equivalent). Prose in planning artifacts may summarize the ADR for humans; the ADR is the canonical decision trace.

### 2.1 Required sections

| Section | Content |
|---------|---------|
| `problem_decomposition` | Subproblems the system must solve (e.g. rendering, input, networking, persistence) |
| `domain_model` | Core entities and relationships (e.g. Player, Snake, Food, Room) |
| `runtime_architecture` | Client/server/process boundaries, communication patterns |
| `data_architecture` | What state exists, where it lives, consistency model |
| `infrastructure_assumptions` | Hosting, protocols, third-party services (if any) |
| `security_assumptions` | Auth, trust boundaries, abuse considerations (planning level) |
| `scaling_assumptions` | Expected load, horizontal scaling posture |
| `build_test_deploy_assumptions` | Toolchain, CI, deployment target |
| `rejected_alternatives` | Options not selected, with brief reason |
| `selected_option` | Recommended architecture (not owner-approved fact) |
| `rationale` | Why the selected option fits goal, constraints, and first slice |
| `reversibility` | Cost-of-change estimate: `LOW` \| `MEDIUM` \| `HIGH` per major choice |
| `unknowns_requiring_owner_validation` | Items the orchestrator cannot settle |

### 2.2 Per-choice traceability

For each significant choice (frontend, networking, backend, persistence, deployment, first slice), the ADR must include:

```json
{
  "choice_id": "networking_model",
  "options": [
    { "id": "websocket_authoritative", "summary": "WebSocket server, server-authoritative state" },
    { "id": "offline_single_player", "summary": "No network; local game loop only" }
  ],
  "selected_option_id": "websocket_authoritative",
  "rationale": "User goal says 'online'; slither.io is multiplayer",
  "reversibility": "HIGH",
  "owner_validation_required": true,
  "status": "RECOMMENDED_NOT_APPROVED"
}
```

`status` must never be `OWNER_APPROVED` unless a separate owner decision record exists.

---

## 3. Slither-like demo — architecture dimensions

For the demo goal `"Build me an online slither.io-like game"`, the orchestrator contract requires explicit treatment of:

| Dimension | Orchestrator must document |
|-----------|---------------------------|
| **Frontend/runtime choice** | e.g. browser Canvas 2D vs WebGL; vanilla JS vs framework |
| **Game loop model** | requestAnimationFrame client loop; server tick if authoritative |
| **Networking model** | WebSocket vs WebRTC; room/lobby model |
| **State synchronization model** | server-authoritative vs client prediction; snapshot frequency |
| **Backend/runtime choice** | Node, Go, static-only phase-1, etc. |
| **Persistence choice** | none for demo, Redis, DB — or deferred |
| **Deployment assumptions** | static CDN, single VPS, local dev only for slice 1 |
| **First implementation slice boundary** | What slice 1 may build without committing to full multiplayer |

The orchestrator **proposes** a coherent package; the owner **validates** before planning artifacts treat choices as constraints.

See [`slither-like-demo-contract.md`](slither-like-demo-contract.md) for a concrete non-executable example.

---

## 4. Mapping ADR → planning artifacts

| ADR content | Planning artifact destination |
|-------------|------------------------------|
| Goal summary, constraints, assumptions | `context-pack.md` draft |
| In-scope/out-of-scope, quality bar | `local-agentic-spec.md` draft |
| Ordered slices, first slice detail | `implementation-plan.md` draft |
| `PLANNING_RUN_SLICE` sketch for slice 1 | Fenced JSON in `implementation-plan.md` |
| Audit checklist items | `planning-audit.md` draft |

**generated Markdown prose is not machine authority.** Only fenced `PLANNING_RUN_SLICE` JSON carries structured slice fields for future import. ADR JSON is authority for architecture traceability, not for execution.

---

## 5. Boundary doctrine (architecture-specific)

| Boundary | Rule |
|----------|------|
| Recommendation vs decision | **architecture recommendation is not owner decision** |
| ADR vs validated plan | ADR draft does not advance `manifest.status` |
| First slice vs full system | First slice boundary must not smuggle full architecture commitment |
| Offline fallback | If user did not confirm "online", orchestrator must not assume multiplayer in slice 1 without flagging `owner_validation_required` |
| Implementation plan | **implementation plan is not runner proposal** |
| Structured slice | **PLANNING_RUN_SLICE is not an approved run** |

---

## 6. Independent validation (architecture)

An independent planning audit pass must verify:

1. **Assumptions** — inferred vs confirmed; no hidden facts
2. **Architecture choices** — options and rejections documented; reversibility stated
3. **Scope boundaries** — non-goals and first slice align with selected architecture
4. **First-slice safety** — slice 1 does not require undeclared infrastructure or undeclared owner approval

Audit may **reject** or **request revision**. Same-context audit must be labeled non-independent. Owner decision remains the final gate after audit.

---

## 7. Non-authority statement

This document does not select architecture for any project, approve infrastructure spending, create runs, or invoke executors. All `selected_option` values are recommendations until the owner records explicit validation in planning decisions or accepted spec revisions.
