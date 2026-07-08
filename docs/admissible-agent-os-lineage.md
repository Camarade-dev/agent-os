# Admissible / Agent OS Lineage and Boundary

## Status

Canonical boundary document for this repository. For file-level classification and import audit evidence, see [`admissible-agent-os-boundary-audit.md`](admissible-agent-os-boundary-audit.md).

## Canonical doctrine

1. **Admissible is the active benchmarkable action-admission layer.**
2. **Agent OS is historical lineage and substrate** — governed-delegation CLI, planning workspaces, evidence registrar, fail-closed closure.
3. **Admissible modules must not import `agent_os`.** Enforced by `tests/test_admissible_boundary.py` (AST import scan + `sys.modules` guard).
4. **The repository name `agent-os` is historical** and does not imply Admissible is a submodule of Agent OS.
5. **Shared repo does not mean shared runtime authority.** Co-location is organizational; object models, schemas, and execution paths are separate.

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

Admissible V0 currently includes:

- a thesis and action-envelope specification;
- a benchmark specification;
- JSON schemas, 25 Tier 1 enriched seed cases, and gold annotations;
- a rules-only reference evaluator, mock frontier-direct baseline runner, scoring harness, comparison runner, run trace generator, static trace viewer, and curated demo pack.

This is a smoke-tested internal harness, not a public benchmark result or production platform.

`docs/v0-release-boundary.md` scopes the Agent OS CLI v0 surface specifically, including its explicit exclusion of a "benchmark framework." That exclusion does not apply to Admissible: Admissible is a separate, sibling initiative living in the same repository, not an extension of the Agent OS v0 CLI boundary.

## Implementation boundary

### Import rule

| Package / tree | May import `agent_os`? | May be imported by `agent_os`? |
|----------------|----------------------|--------------------------------|
| `admissible/` | **No** | No (today) |
| `benchmark/` | **No** | No (today) |
| `agent_os/` | Internal only | N/A |

`benchmark/scoring/` may import `admissible.*`. Admissible runners may import `benchmark.scoring.*`. Neither may reach into `agent_os`.

Existing Agent OS code may inspire Admissible discipline around evidence, authority, fail-closed validation, append-only records, and closure.

However, Agent OS planning artifacts are not Admissible action envelopes.

Agent OS validation reports are not Admissible gold annotations.

Agent OS owner decisions are not Admissible admission decisions.

Admissible implementation should therefore use its own object model.

### What is *not* duplicated

There is no shared Python module between the two systems. Similar words (evidence, owner decision, audit, admissible) refer to **different artifacts** with different schemas and semantics. Treat overlap as vocabulary discipline, not as a signal to import or merge code paths.
