---
plan_id: {{PLAN_ID}}
artifact_type: IMPLEMENTATION_PLAN
created_at: {{CREATED_AT}}
author: PLACEHOLDER
version: 1
status: DRAFT
spec_ref: PLACEHOLDER
---

# Implementation Plan

> **Planning artifact type:** `IMPLEMENTATION_PLAN`

## Spec reference

**Local Agentic Spec:** PLACEHOLDER — path or ID to the accepted `LOCAL_AGENTIC_SPEC` this plan implements.

**Spec version:** PLACEHOLDER

## Plan summary

PLACEHOLDER — how the goal will be achieved across ordered slices. One paragraph; no execution results.

## Ordered slices / runs

| Order | Run label | Mission (summary) | Authority | Dependencies |
|-------|-----------|---------------------|-----------|--------------|
| 1 | PLACEHOLDER | PLACEHOLDER | L0–L4 | — |
| 2 | PLACEHOLDER | PLACEHOLDER | L0–L4 | slice-1 |

---

## Planned run: {{RUN_LABEL_1}}

**Run label:** PLACEHOLDER — stable identifier for this slice (e.g. `slice-01-templates`).

**Mission:** PLACEHOLDER — single bounded outcome for one execution cycle.

**Scope:** PLACEHOLDER — in-scope and out-of-scope for this run.

**allowed_paths:**

```json
[
  "PLACEHOLDER/path/or/glob"
]
```

**authority:** PLACEHOLDER — autonomy level (L0–L4) aligned with Agent OS doctrine.

**expected evidence:** PLACEHOLDER — what closure-grade evidence should look like after execution.

**check_command:** PLACEHOLDER — command to run at invoke time, if any (e.g. `python -m unittest discover -s tests -v`). Leave empty if none.

**stop conditions:** PLACEHOLDER — when the executor must stop without continuing.

**owner gates:** PLACEHOLDER — explicit owner approvals required before or after this slice (e.g. plan acceptance, proposal approval).

**dependencies:** PLACEHOLDER — prior slices or external prerequisites.

---

## Planned run: {{RUN_LABEL_2}}

**Run label:** PLACEHOLDER

**Mission:** PLACEHOLDER

**Scope:** PLACEHOLDER

**allowed_paths:**

```json
[
  "PLACEHOLDER"
]
```

**authority:** PLACEHOLDER

**expected evidence:** PLACEHOLDER

**check_command:** PLACEHOLDER

**stop conditions:** PLACEHOLDER

**owner gates:** PLACEHOLDER

**dependencies:** PLACEHOLDER

---

## Plan revision policy

PLACEHOLDER — when and how this plan may be revised; who may approve revisions; how slice order changes are recorded.

| Version | Date | Author | Change summary | Owner approval |
|---------|------|--------|----------------|----------------|
| 1 | PLACEHOLDER | PLACEHOLDER | Initial plan | PENDING |

## Plan-to-run boundary

**A planned run is not executable until converted into a next-run proposal and approved.**

Mapping to execution is manual or via future runner commands (`propose-next-run` → `approve-next-run` → separate `invoke-run --allow-executor`). The plan does not create run metadata or invoke executors.

---

## Non-authority statement

**This artifact proposes decomposition. It does not create runs, invoke executors, audit work, or approve continuation.**
