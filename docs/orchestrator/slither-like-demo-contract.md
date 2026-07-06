# Slither-like demo contract

> **Status:** contract and example only — **not** autonomous generation output, **not** executable  
> **Slice:** `CORE_ORCHESTRATOR_001`  
> **Companions:** [`goal-to-planning-workspace-contract.md`](goal-to-planning-workspace-contract.md), [`architecture-decision-boundary.md`](architecture-decision-boundary.md), [`../../examples/planning-workspace-slither-like/README.md`](../../examples/planning-workspace-slither-like/README.md)

This document defines the **expected draft outputs** when a future orchestrator receives the demo input. It is a **contract sketch** for reviewers and test authors — not a real orchestrator run, not an approved plan, and not a runner proposal.

---

## 1. Demo input

```
Build me an online slither.io-like game
```

---

## 2. Expected goal intake (draft)

| Field | Expected contract content |
|-------|---------------------------|
| `raw_goal` | `Build me an online slither.io-like game` |
| `normalized_goal` | Browser-based, Slither.io-inspired multiplayer snake game with real-time play over the network |
| `user_visible_summary` | Online Slither-like browser game |
| `explicit_constraints` | (none from user — must be visible as empty, not invented) |
| `inferred_assumptions` | See §2.1 |
| `open_questions` | See §2.2 |
| `non_goals` | Native mobile, monetization, anti-cheat at scale (examples) |
| `risk_flags` | Networking scope creep; ambiguity on "online" vs local-only demo |
| `ambiguity_level` | `HIGH` (until owner confirms multiplayer scope) |
| `planning_readiness` | `REQUIRES_CLARIFICATION` until owner confirms multiplayer scope |

### 2.1 Inferred assumptions (not facts)

| Assumption | Basis | Owner confirmation required |
|------------|-------|---------------------------|
| "Online" implies networked multiplayer | Wording + slither.io reference | yes |
| Browser delivery is acceptable | Common for slither-like clones | yes |
| No specific tech stack stated | Absence in raw goal | yes |

### 2.2 Open questions (visible, not blocking all planning)

| Question | Blocks first slice? |
|----------|---------------------|
| Confirm multiplayer vs offline MVP first? | yes — affects slice 1 boundary |
| Target players per room? | no |
| Keyboard only or touch too? | no |
| Deployment target (local dev vs hosted)? | no for planning draft |

---

## 3. Candidate architecture options (must be listed)

The orchestrator draft must list at least two coherent options before selecting a demo recommendation.

### Option A — Phased: offline browser MVP first

| Dimension | Choice |
|-----------|--------|
| Frontend | Canvas 2D, vanilla JS |
| Game loop | `requestAnimationFrame` client-side |
| Networking | None in phase 1 |
| Backend | None |
| Persistence | None |
| Deployment | Static files / simple static server |
| First slice | Scaffold + local snake loop (aligns with [`examples/planning-workspace-slither-like/`](../../examples/planning-workspace-slither-like/)) |

### Option B — Full online: WebSocket multiplayer

| Dimension | Choice |
|-----------|--------|
| Frontend | Canvas 2D, vanilla JS |
| Game loop | Client render + server tick (e.g. 20 Hz) |
| Networking | WebSocket, room per match |
| State sync | Server-authoritative positions |
| Backend | Node or Go WebSocket server |
| Persistence | Optional leaderboard later |
| Deployment | Static client + VPS/container for server |
| First slice | Repo scaffold + WS handshake stub (no full game) |

### Rejected without documentation

Silently picking Option A or B without listing the other violates the architecture contract.

---

## 4. Selected demo architecture (recommendation only)

For this **demo contract**, the orchestrator would **recommend** Option A for first implementation slice safety, with Option B documented as the target end-state if the owner confirms multiplayer.

| Field | Contract value |
|-------|----------------|
| `selected_option_id` | `phased_offline_mvp_first` |
| `rationale` | High ambiguity on "online"; offline MVP validates game loop before irreversible networking investment; reversibility of networking choice is HIGH |
| `reversibility` | Adding WebSocket layer later: HIGH cost but planned path documented |
| `status` | `RECOMMENDED_NOT_APPROVED` |
| **architecture recommendation is not owner decision** | Owner must confirm phased vs full-online before transition |

### Architecture dimensions (explicit)

| Dimension | Demo recommendation |
|-----------|---------------------|
| Frontend/runtime | Browser, Canvas 2D, vanilla JS |
| Game loop model | Client `requestAnimationFrame`; fixed timestep optional in slice 3+ |
| Networking model | Deferred to post-MVP phase; documented in open questions |
| State synchronization | N/A for slice 1–N offline MVP |
| Backend/runtime | None for first slices |
| Persistence | None |
| Deployment assumptions | Local static server or `file://` for demo |
| First implementation slice boundary | Scaffold only — HTML/CSS/JS stubs, no game logic |

---

## 5. First implementation slice (draft)

**Slice label:** `slice-001-scaffold` (or aligned `slice-02-scaffold` in example workspace numbering)

| Field | Draft value |
|-------|-------------|
| Mission | Create minimal `slither-demo/` with `index.html`, `style.css`, `game.js` stubs |
| Scope | Scaffold files only; no game loop or snake logic |
| Authority | L2 (when eventually proposed as run — not in this contract) |
| Dependencies | Owner confirmation on phased vs online approach |

---

## 6. First `PLANNING_RUN_SLICE` sketch (non-executable)

The draft `implementation-plan.md` may include a fenced JSON block like the example in [`examples/planning-workspace-slither-like/implementation-plan.md`](../../examples/planning-workspace-slither-like/implementation-plan.md).

**Contract requirements for the sketch:**

- `artifact_type` must be `PLANNING_RUN_SLICE`
- `non_authority` block must be present per [`../planning-structured-slice-format.md`](../planning-structured-slice-format.md)
- **PLANNING_RUN_SLICE is not an approved run**
- Sketch does not create proposals; **runner import remains explicit**

Illustrative excerpt (contract only):

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

## 7. Audit checklist (draft)

The orchestrator draft must include a `planning-audit.md` checklist (not a PASS verdict). Minimum items:

| # | Check |
|---|-------|
| 1 | Inferred assumptions labeled; "online" ≠ confirmed multiplayer |
| 2 | Options A and B documented; recommendation traceable |
| 3 | First slice excludes networking if phased approach selected |
| 4 | Open question on multiplayer confirmation has `blocks_first_slice` or equivalent visibility |
| 5 | `PLANNING_RUN_SLICE` sketch contains `non_authority` |
| 6 | No prose implies owner approval or execution |
| 7 | **planning draft is not a validated workspace** |
| 8 | **implementation plan is not runner proposal** |
| 9 | Independent audit pass required before owner approval |
| 10 | **executor invocation remains separate** |

---

## 8. What this demo contract is not

| Not this | Because |
|----------|---------|
| Real orchestrator output | No LLM adapter or generator implemented |
| Validated planning workspace | No `planning validate` run on orchestrator output |
| Approved plan | **goal intake is not planning approval** |
| Runner proposal | **runner import remains explicit**; separate repo and gate |
| Executable slice | **executor invocation remains separate** |
| Machine authority from Markdown | **generated Markdown prose is not machine authority** |

---

## 9. Relation to existing example workspace

[`examples/planning-workspace-slither-like/`](../../examples/planning-workspace-slither-like/) demonstrates an **offline** Slither-like plan (EXAMPLE_ONLY). This demo contract extends the **orchestrator** story for an **online** goal while recommending a safe phased first slice. The example workspace remains authoritative for layout and `PLANNING_RUN_SLICE` format; this document is authoritative for orchestrator expected behavior only.

No files in `agent-os-runner-experimental` are modified or required by this slice.
