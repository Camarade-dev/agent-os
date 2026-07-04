# Thesis

Agent OS is a **local epistemic protocol** for governed agentic execution.

## Problem

Coding and research agents are fallible. Owners delegate work without a durable structure for mission, authority, evidence, audit, and closure. Ad-hoc chat threads collapse context, hide assumptions, and make it hard to know when work is truly done.

## Position

Agent OS is **not**:

- a dashboard or agent panel
- a SaaS product
- an orchestration platform
- a benchmark system
- an autonomous agent runtime

Agent OS **is**:

- a filesystem-local protocol
- a set of markdown primitives and templates
- a fail-closed closure discipline
- a memory hygiene practice for long-running delegation

## Core claim

Governed delegation requires **separation of concerns** between:

1. what was asked (mission)
2. what was permitted (authority / autonomy gates)
3. what was done (evidence)
4. what was verified (audit)
5. what the owner accepts (owner decision)
6. how the run ends (closure)
7. what persists afterward (memory update)

## v0 intent

Version 0 establishes the repository skeleton, templates, documentation, and a minimal CLI that can bootstrap `.agent-os/` workspaces in arbitrary local projects. It does not execute agents. It structures human–agent collaboration.
