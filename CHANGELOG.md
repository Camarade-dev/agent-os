# Changelog

## Admissible OpenAI Build Week submission — 2026-07-21

Submission hardening for the final Admissible product, distinct from the
historical Agent OS v0.1.0 release below.

### Product surface

- Added the governed native product launcher and authenticated loopback service.
- Added browser compose/authorize and result/evidence flows.
- Added independent evidence reconstruction with authoritative accepted/refused
  presentation.
- Added the verified incident-replay workflow, governed rerun recovery, and
  behavioral/backend authority consistency.

### Submission

- Made the source-controlled product UI assets installable with the Python
  distribution.
- Added the `admissible` launcher entry point while preserving `agent-os`.
- Added provider-free judge instructions, Build Week provenance, security
  boundaries, and the root MIT license.

## v0.1.0 — 2026-07-04

Initial local governed-delegation prototype.

### Added

- Stdlib-only Python CLI (`agent-os`) installable from source (`pip install -e .`)
- `.agent-os/` workspace and per-run structure under `.agent-os/runs/<run-id>/`
- Packaged markdown templates: mission, preflight, evidence, audit, owner-decision, closure, memory-update
- CLI commands: `init`, `mission`, `status`, `audit`, `close`
- Fail-closed closure validation with required-field checks and already-closed guard
- Protocol documentation: thesis, primitives, operating loop, autonomy levels, memory hygiene, v0 release boundary

### Evidence stack

Registrar-only evidence helpers (capture, not judgment):

- `evidence add` — append structured evidence notes
- `evidence add-file` — register on-disk file paths (reference only)
- `evidence add-command-output` — register command string and owner-supplied output (no execution)
- `evidence snapshot-git` — read-only Git snapshot via fixed allowlist (`status --porcelain`, `diff --stat`)
- `evidence list` — read-only index of structured evidence entries

See `docs/evidence-capture-doctrine-v0.md` and `docs/evidence-capture-boundaries-v0.md`.

### Validated

- 71 passing tests (`python -m unittest discover -s tests -v`)
- Dogfood 001 — todo CLI (end-to-end protocol mechanics)
- Dogfood 002 — Markdown evidence pack (medium-scope local CLI)
- Dogfood 003 — local site audit (scope pressure, frozen core)
- Dogfood 004 — JSON config linter (full evidence stack in one closure)

### Explicitly out of scope

- Agent execution, orchestration, scheduling, or multi-agent coordination
- Dashboards, UI, SaaS, cloud, API server, multi-user, auth, or billing
- LLM calls, auto-audit, auto-close, or guided fill
- Arbitrary command execution, generic shell runner, or automatic evidence capture on close
- Full artifact archive, copy, or hashing
- Benchmark framework, CI, or release automation
- Breezly content or a root `.agent-os/` workspace in the core repository
