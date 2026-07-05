---
plan_id: slither-like-example
artifact_type: PLANNING_AUDIT
created_at: 2026-07-05T00:00:00Z
auditor: EXAMPLE_AUDITOR
version: 1
example_only: true
---

# Planning Audit

> **Planning artifact type:** `PLANNING_AUDIT`  
> **EXAMPLE_ONLY** — illustrates audit structure; not a live verdict for execution.

## Artifacts audited

| Artifact type | Path / ID | Version | Status at audit |
|---------------|-----------|---------|-----------------|
| Goal | manifest.json | — | EXAMPLE_ONLY |
| CONTEXT_PACK | context-pack.md | 1 | draft complete |
| LOCAL_AGENTIC_SPEC | local-agentic-spec.md | 1 | ambiguities PENDING |
| IMPLEMENTATION_PLAN | implementation-plan.md | 1 | 8 slices defined |
| Next Run Proposal | N/A | — | none |

## Completeness checks

| Check | Result | Notes |
|-------|--------|-------|
| Context Pack has goal reference and source boundaries | pass | EXAMPLE_ONLY pack |
| Local Agentic Spec has in/out scope and non-goals | pass | — |
| Implementation Plan cites spec and lists ordered slices | pass | 8 slices |
| Each planned run has mission, scope, authority, stop conditions | pass | All slices documented |

## Scope consistency checks

| Alignment | Result | Notes |
|-----------|--------|-------|
| Goal ↔ Context Pack | pass | Static browser game |
| Context Pack ↔ Local Agentic Spec | pass | No backend |
| Local Agentic Spec ↔ Implementation Plan | pass with notes | Spec ambiguities still PENDING |
| Planned slices ↔ goal success criteria | pass | Final slice addresses README |

## Allowed path consistency checks

| Run label | Scope text vs allowed_paths | Result | Notes |
|-----------|----------------------------|--------|-------|
| slice-02-scaffold | `slither-demo/*` | pass | Structured paths |
| slice-01-spec-confirmation | planning paths only | pass | No game code |

## Check command feasibility

| Run label | check_command | Feasible | Notes |
|-----------|---------------|----------|-------|
| all slices | (none declared) | n/a | Manual browser verification |

## Spec drift risks

| Risk | Severity | Mitigation recorded |
|------|----------|---------------------|
| EXAMPLE_ONLY plan imported as real | low | `example_only: true` in manifest |
| Skip planning audit before propose | medium | Gate `planning-audit-required` in manifest |

## Verdict

**Verdict:** `PASS_WITH_NOTES` (illustrative — EXAMPLE_ONLY)

**Summary:** Artifacts are structurally complete for documentation purposes. Real use would require owner resolution of spec ambiguities and explicit non-EXAMPLE manifest before `APPROVED_FOR_RUN_PROPOSALS`.

### Verdict definitions

| Verdict | Meaning |
|---------|---------|
| `PASS` | Planning artifacts complete and consistent; plan-driven proposals may proceed subject to owner gates. |
| `PASS_WITH_NOTES` | Proceed with documented caveats. |
| `FAIL` | Revise artifacts before proposal. |
| `BLOCKED` | Owner decision required. |

## Required fixes

| # | Fix | Owner | Status |
|---|-----|-------|--------|
| 1 | Resolve canvas size and speed ambiguities | EXAMPLE_OWNER | open (example) |
| 2 | Set `example_only: false` and re-audit for real use | Owner | n/a for sample |

---

## Non-authority statement

**This artifact audits planning quality. It does not approve execution or invoke agents.**
