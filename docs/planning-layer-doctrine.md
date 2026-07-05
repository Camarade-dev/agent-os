# Governed planning layer — doctrine

> **Status:** doctrine only — no CLI commands, no validation rules, no automation  
> **Relation to Agent OS:** extension layer; not part of Agent OS v0.1.0 core behavior  
> **Audit conclusion:** compatible with Agent OS when artifact-based, gate-separated, manual-first, non-orchestrating, and role-bounded

This document formalizes the **governed planning layer** before any implementation. It defines why planning exists, the artifact chain, role boundaries, authority, hard prohibitions, and what the layer must never become.

Companion (experimental runner): `agent-os-runner-experimental/docs/planning-to-run-boundary.md` — how planning artifacts feed run metadata and executor gates.

---

## 1. Why governed planning is needed

Agent OS v0 structures **execution governance**: mission, scope, authority, evidence, audit, owner decision, and closure for a single bounded run. That is sufficient when the owner already knows what to delegate and can write mission/scope directly.

Governed planning is needed when:

- **Intent precedes execution** — the owner has a goal but not yet a bounded, reviewable run definition.
- **Context is scattered** — repository state, prior runs, constraints, and open questions must be assembled before scoping work.
- **Delegation risk is high** — multi-step programs, cross-cutting changes, or ambiguous scope require explicit planning artifacts before any executor is invoked.
- **Separation of concerns must hold** — planners propose; owners approve; executors act; auditors verify; owners accept. Collapsing these roles into one agent loop destroys auditability.

Without a planning layer, owners either skip structure (ad-hoc prompts) or overload run artifacts with pre-execution reasoning (polluting the execution record). The planning layer holds **pre-run reasoning** in inspectable artifacts that feed — but do not replace — governed execution.

Planning does **not** make agents trustworthy. It makes **what was planned, by whom, and under what authority** inspectable before execution begins.

---

## 2. Artifact chain

Planning and execution form a **linear, gate-separated chain**. Each arrow is a manual transition; no step auto-advances the next.

```
Goal
  │
  ▼
Context Pack
  │
  ▼
Local Agentic Spec
  │
  ▼
Implementation Plan
  │
  ▼
Next Run Proposal
  │
  ▼
Approved Run          ← owner approval gate
  │
  ▼
Execution             ← explicit executor authorization
  │
  ▼
Evidence
  │
  ▼
Audit
  │
  ▼
Owner Decision
  │
  ▼
Closure
```

| Stage | Artifact / state | Purpose |
|-------|------------------|---------|
| **Goal** | Owner-stated objective | Why work exists; not yet bounded |
| **Context Pack** | Assembled read-only context | What the planner may consider |
| **Local Agentic Spec** | Bounded agent instructions | What an agent may do in planning (not execution) |
| **Implementation Plan** | Reviewable work breakdown | What runs should accomplish, in what order |
| **Next Run Proposal** | Proposed bounded run | Intent for one execution cycle; no run metadata yet |
| **Approved Run** | Owner-approved run definition | Executable metadata may be created |
| **Execution** | External agent work | Bounded by approved mission/scope/authority |
| **Evidence** | Inspectable proof | What happened; supports audit |
| **Audit** | Independent verdict | Whether evidence meets mission/scope |
| **Owner Decision** | ACCEPT / REJECT | Owner judgment; not self-certification |
| **Closure** | Terminal run disposition | Fail-closed completion of one cycle |

After closure, the chain may restart at **Goal** revision, **Context Pack** refresh, **Implementation Plan** update, or a new **Next Run Proposal** — always through explicit owner or role-bounded steps. There is no autonomous loop.

---

## 3. Artifact definitions

### Context Pack

A **Context Pack** is a read-oriented assembly of material the planning roles may use to understand the problem space.

**Contains (examples):**

- Goal statement and success criteria (draft or owner-approved)
- Repository pointers (paths, not mutations)
- Prior run summaries, closure verdicts, audit notes
- Open questions, constraints, non-goals
- References to external docs, issues, or decisions

**Does not contain:**

- Executable commands disguised as context
- Implicit approval to modify the repository
- Audit verdicts or owner decisions

**Storage:** inspectable files under a planning workspace (e.g. `.agent-os/planning/<plan-id>/context-pack.md` or equivalent). Format is markdown or structured JSON; implementation is post-doctrine.

### Local Agentic Spec

A **Local Agentic Spec** defines how a planning agent (human or external tool) may assist **within the planning layer only**.

**Contains:**

- Role assignment (e.g. Context Collector, Local Spec Writer)
- Allowed read paths and forbidden write paths
- Output schema (what artifacts the agent may produce)
- Stop conditions and escalation rules
- Explicit statement: this spec does **not** authorize execution or repo mutation unless a separate owner grant exists

**Does not contain:**

- Mission/scope for an execution run (that belongs in Implementation Plan → Next Run Proposal)
- Self-approval language
- Executor invocation instructions

Generated specs are **proposals**. An owner or designated approver must accept or revise before the spec governs any agent session.

### Implementation Plan

An **Implementation Plan** is the reviewable breakdown of how the goal will be achieved across one or more bounded runs.

**Contains:**

- Phases or slices with ordering rationale
- Per-slice: mission, scope, authority level, allowed paths (structured when possible)
- Expected evidence and check commands (declared, not executed by the planner)
- Stop conditions and rollback notes
- Dependencies between slices
- Plan revision history and version identifier

**Does not contain:**

- Live execution results
- Audit verdicts
- Automatic scheduling or daemon configuration

The plan is the **source document** from which **Next Run Proposals** are derived. One plan may yield many proposals over time; proposals must cite the plan slice they implement.

### Planning Evidence

**Planning Evidence** is inspectable material that supports claims made during planning (not during execution).

**Examples:**

- Context Pack source citations
- Diffs between spec revisions
- Owner notes on plan acceptance
- Checklists showing required fields were filled before proposal

Planning evidence informs **Planning Audit**. It must not be substituted for execution evidence at run closure.

### Planning Audit

A **Planning Audit** is an independent review of planning artifacts before execution is authorized.

**Reviews:**

- Goal ↔ Context Pack alignment
- Local Agentic Spec ↔ role boundaries
- Implementation Plan ↔ goal and constraints
- Next Run Proposal ↔ plan slice (no scope creep, no missing stop conditions)

**Produces:**

- Verdict: `PASS`, `PASS_WITH_NOTES`, `FAIL`, or `INCONCLUSIVE`
- Notes on gaps, drift, or authority violations

Planning audit is **separate from execution audit**. A passed planning audit does not pass an execution run. Execution audit weighs execution evidence against the **approved run**, not the plan in isolation.

---

## 4. Role boundaries

Each role is **bounded**. One human or agent session should not combine incompatible roles in a single ungoverned step.

| Role | May do | Must not do |
|------|--------|-------------|
| **Context Collector** | Read repo and prior artifacts; assemble Context Pack | Write implementation code; approve plans; invoke executor |
| **Local Spec Writer** | Draft or revise Local Agentic Spec within owner constraints | Execute planned work; audit; owner-accept |
| **Implementation Planner** | Produce or revise Implementation Plan from context and spec | Create run metadata; invoke executor; record execution audit |
| **Run Proposer** | Derive Next Run Proposal from an approved plan slice | Approve own proposal; invoke executor; mutate repo (unless explicitly authorized for proposal tooling only) |
| **Executor** | Perform bounded work per approved run mission/scope/authority | Plan next runs; audit own work; owner-accept; close runs without evidence |
| **Auditor** | Review evidence (planning or execution) and record verdict | Execute work; owner-accept; approve next runs |
| **Owner** | Approve specs and plans; approve/reject proposals; ACCEPT/REJECT runs; authorize closure | Substitute for independent audit when separation is required by policy |

Roles may be held by the same person in solo use, but **artifacts and gates must still separate** planning, approval, execution, audit, and acceptance. The protocol makes collisions visible.

---

## 5. Authority matrix

Legend: **R** read, **W** write, **P** propose, **A** approve, **X** execute, **U** audit, **C** close (owner disposition)

| Artifact / action | Context Collector | Local Spec Writer | Implementation Planner | Run Proposer | Executor | Auditor | Owner |
|-------------------|:-----------------:|:-----------------:|:----------------------:|:------------:|:--------:|:-------:|:-----:|
| Goal | R | R | R | R | R | R | R/W |
| Context Pack | W | R | R | R | R | R | A |
| Local Agentic Spec | R | W/P | R | R | — | R | A |
| Implementation Plan | R | R | W/P | R | R | R | A |
| Next Run Proposal | — | — | R | W/P | — | R | A |
| Approved Run metadata | — | — | R | R | R | R | A |
| Execution / repo changes | — | — | — | — | X* | R | A* |
| Execution evidence | — | — | — | — | W | R | R |
| Planning evidence | W | W | W | W | — | R | R |
| Planning audit | — | — | — | — | — | U | R |
| Execution audit | — | — | — | — | — | U | R |
| Owner decision | — | — | — | — | — | — | W |
| Run closure | — | — | — | — | — | — | C |

\* Executor may mutate repo only within approved run scope and authority. Owner authorizes executor invocation explicitly (see runner boundary doc).

**Approve** means an explicit recorded decision — not implicit continuation. **Close** means owner disposition through fail-closed closure gates (Agent OS `close` or runner equivalent).

---

## 6. Hard prohibitions

These rules are **non-negotiable** for a compatible planning layer:

| # | Prohibition | Rationale |
|---|-------------|-----------|
| 1 | **Planner must not execute** | Planning produces proposals; execution is a separate role and gate |
| 2 | **Executor must not audit** | Auditors must be independent of the work under review |
| 3 | **Auditor must not owner-accept** | Acceptance is owner authority; audit informs only |
| 4 | **Generated spec must not self-approve** | Local Agentic Spec is a draft until owner or policy approver accepts |
| 5 | **Next run must not auto-execute** | Approval creates metadata at most; invocation requires a separate explicit authorization |
| 6 | **Planning agent must not mutate repo unless explicitly authorized** | Context collection is read-first; any write requires a named grant in spec or owner instruction |
| 7 | **Planning audit must not substitute for execution audit** | Different evidence, different gates |
| 8 | **Closure must not auto-follow audit** | Owner decision and closure remain explicit (Agent OS fail-closed model) |
| 9 | **No daemon, scheduler, or background loop** | All transitions are manual CLI or owner action |

Violations are **process defects**, not features to automate away.

---

## 7. Anti-orchestration boundary

Planning artifacts are **not** an autonomous loop.

The planning layer must never:

- Poll for completion and automatically start the next phase
- Chain LLM calls from Context Pack → Spec → Plan → Proposal → Invoke without owner gates
- Treat a passed planning audit as permission to invoke an executor
- Rewrite run metadata or evidence to “heal” failed audits
- Schedule retries, backoff, or multi-agent handoffs without explicit operator commands

```
┌─────────────────────────────────────────────────────────────┐
│  PLANNING LAYER (artifacts only, manual transitions)        │
│  Goal → Context → Spec → Plan → Proposal                    │
└───────────────────────────┬─────────────────────────────────┘
                            │ owner approves proposal
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  EXECUTION LAYER (Agent OS run / runner run metadata)       │
│  Approved Run → Execution → Evidence → Audit → Owner → Close│
└─────────────────────────────────────────────────────────────┘
```

If a tool behaves like an orchestrator — watching state and firing the next step — it is **out of doctrine**, regardless of whether it uses the word “planning.”

---

## 8. Relation to Agent OS v0.1.0

Agent OS v0.1.0 provides:

- Single-run artifact templates under `.agent-os/runs/<run-id>/`
- Registrar-only evidence helpers
- Fail-closed closure
- Explicit `audit` and `close` commands
- No agent invocation, no orchestration, no planning workspace

The governed planning layer is a **doctrine extension only**:

- It does not change v0.1.0 CLI behavior, templates, or validation
- It does not add commands to core in this slice
- Planning artifacts may live alongside `.agent-os/` (e.g. `.agent-os/planning/`) or in a sibling experimental layout; that is an implementation choice post-doctrine
- Execution still terminates in the same run lifecycle: evidence → audit → owner decision → closure

Dogfood and release boundary documents remain authoritative for v0 core. This document is authoritative for **pre-execution planning** only.

---

## 9. Non-goals

The planning layer doctrine explicitly **does not** target:

| Non-goal | Notes |
|----------|-------|
| **SaaS** | Local artifacts and CLI only |
| **Daemon / background worker** | Manual-first transitions |
| **Autonomous scheduler** | No cron, no queue consumer, no “run until done” |
| **Multi-agent marketplace** | No agent discovery, bidding, or coordination bus |
| **Cursor-specific doctrine** | Cursor may be one executor adapter; planning roles are tool-agnostic |
| **Auto-audit / auto-close** | Same separation as Agent OS v0 |
| **Trust engine** | Planning structures claims; it does not certify truth |

---

## 10. Recommended implementation order (post-doctrine)

1. Planning workspace layout and artifact templates (docs + files only)
2. Planning audit checklist (manual)
3. Implementation Plan → Next Run Proposal field mapping (runner boundary)
4. Structured `allowed_paths` in proposals (runner)
5. Deprecation path for legacy `next-run` without proposal (runner)

No step above is authorized by this document alone. Owner must approve each implementation slice.

---

## 11. References

- `docs/v0-release-boundary.md` — Agent OS v0.1.0 core boundary
- `docs/operating-loop.md` — execution lifecycle
- `docs/evidence-capture-doctrine-v0.md` — execution evidence doctrine
- `docs/autonomy-levels.md` — authority levels for runs
- `agent-os-runner-experimental/docs/planning-to-run-boundary.md` — plan → runner mapping
