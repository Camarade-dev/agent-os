---
plan_id: {{PLAN_ID}}
artifact_type: PLANNING_AUDIT
created_at: {{CREATED_AT}}
auditor: PLACEHOLDER
version: 1
---

# Planning Audit

> **Planning artifact type:** `PLANNING_AUDIT`

## Artifacts audited

| Artifact type | Path / ID | Version | Status at audit |
|---------------|-----------|---------|-----------------|
| Goal | PLACEHOLDER | — | PLACEHOLDER |
| CONTEXT_PACK | PLACEHOLDER | PLACEHOLDER | PLACEHOLDER |
| LOCAL_AGENTIC_SPEC | PLACEHOLDER | PLACEHOLDER | PLACEHOLDER |
| IMPLEMENTATION_PLAN | PLACEHOLDER | PLACEHOLDER | PLACEHOLDER |
| Next Run Proposal | PLACEHOLDER / N/A | PLACEHOLDER | PLACEHOLDER |

## Completeness checks

PLACEHOLDER — required sections and fields present in each artifact.

| Check | Result | Notes |
|-------|--------|-------|
| Context Pack has goal reference and source boundaries | pass / fail / n/a | PLACEHOLDER |
| Local Agentic Spec has in/out scope and non-goals | pass / fail / n/a | PLACEHOLDER |
| Implementation Plan cites spec and lists ordered slices | pass / fail / n/a | PLACEHOLDER |
| Each planned run has mission, scope, authority, stop conditions | pass / fail / n/a | PLACEHOLDER |

## Scope consistency checks

PLACEHOLDER — goal ↔ spec ↔ plan alignment; no scope creep between artifacts.

| Alignment | Result | Notes |
|-----------|--------|-------|
| Goal ↔ Context Pack | pass / fail | PLACEHOLDER |
| Context Pack ↔ Local Agentic Spec | pass / fail | PLACEHOLDER |
| Local Agentic Spec ↔ Implementation Plan | pass / fail | PLACEHOLDER |
| Planned slices ↔ goal success criteria | pass / fail | PLACEHOLDER |

## Allowed path consistency checks

PLACEHOLDER — `allowed_paths` on each slice are structured, non-overlapping where required, and consistent with stated scope.

| Run label | Scope text vs allowed_paths | Result | Notes |
|-----------|----------------------------|--------|-------|
| PLACEHOLDER | PLACEHOLDER | pass / fail | PLACEHOLDER |

## Check command feasibility

PLACEHOLDER — declared `check_command` values are explicit, runnable in the target environment, and not disguised execution during planning.

| Run label | check_command | Feasible | Notes |
|-----------|---------------|----------|-------|
| PLACEHOLDER | PLACEHOLDER | yes / no / n/a | PLACEHOLDER |

## Spec drift risks

PLACEHOLDER — risks that planning artifacts could be misread to authorize execution or bypass gates.

| Risk | Severity | Mitigation recorded |
|------|----------|---------------------|
| PLACEHOLDER | low / medium / high | PLACEHOLDER |

## Verdict

**Verdict:** PLACEHOLDER — one of: `PASS`, `PASS_WITH_NOTES`, `FAIL`, `BLOCKED`

**Summary:** PLACEHOLDER — one paragraph explaining the verdict.

### Verdict definitions

| Verdict | Meaning |
|---------|---------|
| `PASS` | Planning artifacts are complete and consistent; plan-driven proposals may proceed subject to owner approval gates. |
| `PASS_WITH_NOTES` | Proceed with documented caveats; notes must be acknowledged before proposal. |
| `FAIL` | Material gaps or inconsistencies; revise artifacts before proposal. |
| `BLOCKED` | External or owner decision required; cannot proceed until unblocked. |

## Required fixes

PLACEHOLDER — if verdict is `FAIL` or `BLOCKED`, list required fixes. If `PASS` or `PASS_WITH_NOTES`, list optional follow-ups.

| # | Fix | Owner | Status |
|---|-----|-------|--------|
| 1 | PLACEHOLDER | PLACEHOLDER | open / done |

---

## Non-authority statement

**This artifact audits planning quality. It does not approve execution or invoke agents.**
