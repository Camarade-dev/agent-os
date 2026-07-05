# Planning workspace — Slither-like example

> **EXAMPLE_ONLY** — This directory is a **documentation sample**, not an active planning package and not approved for execution.

## Purpose

Demonstrates the layout defined in [`docs/planning-workspace-layout.md`](../../docs/planning-workspace-layout.md). In a real project, this content would live at:

```
.agent-os/planning/<plan-id>/
```

## Contents

| File | Role |
|------|------|
| `manifest.json` | Identity, status, gates (sample values) |
| `context-pack.md` | Assembled context for the example goal |
| `local-agentic-spec.md` | Bounded planning intent |
| `implementation-plan.md` | Eight ordered slices (not executable) |
| `planning-audit.md` | Sample audit (verdict left as illustration) |

Subdirectories `evidence/`, `decisions/`, and `revisions/` would appear in a live workspace; omitted here for brevity.

## Non-authority notice

**This sample does not approve work, create runs, invoke agents, or authorize repository changes.** Copy templates from `agent_os/templates/planning/` and follow the layout doc when creating a real plan.
