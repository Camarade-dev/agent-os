# Admissible / Agent OS Lineage and Boundary

## Status

This document clarifies the relationship between Agent OS and Admissible.

## Summary

Agent OS is the prior/internal governed-delegation substrate.

Admissible is the current benchmark/spec/prototype direction focused on execution-boundary action admission for side-effecting AI-agent actions.

## Agent OS

Agent OS focuses on governed delegation, planning artifacts, evidence capture, owner decisions, closure, and fail-closed validation for coding-agent workflows.

## Admissible

Admissible focuses on benchmarkable action admission at the execution boundary.

Canonical Admissible objects include:

- action envelope;
- admission decision;
- gold annotation;
- benchmark case;
- run trace;
- scoring result;
- baseline;
- final verdict.

Canonical Admissible labels are:

- ALLOW
- ALLOW_WITH_LIMITS
- REQUEST_MORE_EVIDENCE
- REQUIRE_HUMAN_APPROVAL
- REFUSE

See `docs/Admissible_THESIS.md`, `docs/Admissible_ACTION_ENVELOPE.md`, and `docs/Admissible_BENCHMARK_SPEC.md` for the full specification.

## Vocabulary boundary

Agent OS uses "admissible" or "admissible for promotion" to mean that a planning or requirements artifact is structurally ready for a later owner decision. This phrasing appears in the orchestrator CLI (`agent_os/cli.py`, `agent_os/orchestrator.py`) and in `docs/orchestrator/goal-intake-artifact.md` and `docs/orchestrator/goal-to-planning-workspace-contract.md`.

This is not the same as Admissible action admissibility.

Admissible action admissibility means that a proposed side-effecting AI-agent action may be admitted into execution under authority, evidence, policy, risk, provenance, auditability, and responsibility constraints.

## Owner decisions vs action approval

Agent OS owner decisions govern whether internal planning artifacts may be promoted to the next stage of a coding workflow.

Admissible `REQUIRE_HUMAN_APPROVAL` means that a human or authority-bearing role must approve a specific side-effecting action before execution.

These concepts are related but not interchangeable.

## Scope boundary

Admissible V0 is not:

- an Agent OS v0 CLI extension;
- a SaaS product;
- a production platform;
- a generic orchestration framework;
- a renamed Agent OS orchestrator;
- a full enterprise dashboard.

Admissible V0 is currently:

- a thesis;
- an action-envelope specification;
- a benchmark specification;
- a future schema/case/scoring/runner harness.

`docs/v0-release-boundary.md` scopes the Agent OS CLI v0 surface specifically, including its explicit exclusion of a "benchmark framework." That exclusion does not apply to Admissible: Admissible is a separate, sibling initiative living in the same repository, not an extension of the Agent OS v0 CLI boundary.

## Implementation boundary

Existing Agent OS code may inspire Admissible discipline around evidence, authority, fail-closed validation, append-only records, and closure.

However, Agent OS planning artifacts are not Admissible action envelopes.

Agent OS validation reports are not Admissible gold annotations.

Agent OS owner decisions are not Admissible admission decisions.

Admissible implementation should therefore use its own object model.
