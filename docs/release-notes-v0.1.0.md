# Agent OS v0.1.0 — release notes

**Release date:** 2026-07-04  
**Tag:** `v0.1.0`  
**Tag target:** `e20d9199ecaf52856e24bb8f1792881fcd862b2a`  
**Tag message:** Agent OS v0.1.0 local governed-delegation prototype

---

## What Agent OS v0.1.0 is

Agent OS v0.1.0 is a **local filesystem protocol and stdlib-only Python CLI** for governed agentic delegation. It helps a human owner delegate work to fallible coding and research agents by making mission, scope, authority, evidence, audit, owner decision, and closure explicit and inspectable on disk.

The protocol lives in markdown artifacts under `.agent-os/` inside projects that adopt it. The CLI bootstraps workspaces, creates runs from templates, surfaces blocking fields, records audit verdicts, registers evidence, and attempts fail-closed closure.

This release is a **local prototype**. It structures claims and ceremony; it does not execute agents or replace owner judgment.

## What it is not

Agent OS v0.1.0 is **not**:

- a dashboard, agent panel, or UI
- an agent runtime, executor, or orchestrator
- a SaaS product, cloud service, or API server
- a benchmark framework or trust engine that certifies agent output
- a tool that calls LLMs, auto-audits, or auto-closes runs

See [`v0-release-boundary.md`](v0-release-boundary.md) for the formal scope boundary.

## Main CLI surface

```bash
agent-os init [PATH]          # bootstrap .agent-os/ in a target project
agent-os mission [PATH]       # create a new run from templates
agent-os status [PATH]        # list runs and fields blocking closure
agent-os audit RUN_ID [PATH]  # record an audit verdict
agent-os close RUN_ID [PATH]  # attempt fail-closed run closure
```

Evidence helpers (registrar-only):

```bash
agent-os evidence add RUN_ID [PATH] --note "..."
agent-os evidence add-file RUN_ID [PATH] --file <path> --note "..."
agent-os evidence add-command-output RUN_ID [PATH] --command "..." --output-file <path> --note "..."
agent-os evidence snapshot-git RUN_ID [PATH] --note "..." [--repo <path>] [--no-include-diff-stat]
agent-os evidence list RUN_ID [PATH]
```

Install from source: `pip install -e .` (Python 3.10+, no runtime dependencies).

## Evidence stack

Agent OS v0 provides a layered evidence stack. Each layer captures material; none judges whether closure should succeed.

| Helper | What it captures |
|--------|------------------|
| `evidence add` | Owner- or agent-supplied text tied to a claim |
| `evidence add-file` | Path to an on-disk artifact (no copy, no hash) |
| `evidence add-command-output` | Command string + owner-supplied output file (no execution) |
| `evidence snapshot-git` | Read-only `git status --porcelain` and `git diff --stat` |
| `evidence list` | Read-only structured index of registered entries |

Free-form content in `evidence.md` remains valid. Structured helpers append typed blocks that `evidence list` can index.

**Capture vs judgment:** helpers register evidence; audit, owner decision, and closure gate check presence of required fields — not whether evidence is sufficient for acceptance.

See [`evidence-capture-doctrine-v0.md`](evidence-capture-doctrine-v0.md) and [`evidence-capture-boundaries-v0.md`](evidence-capture-boundaries-v0.md).

## Fail-closed closure

Closure requires all of the following to be filled:

- mission statement
- scope
- authority
- autonomy level or autonomy gates
- at least one evidence item
- audit verdict
- owner decision
- closure verdict

`agent-os close` exits non-zero and lists blocking fields until the ceremony is complete. Re-closing an already-closed run is guarded (exit code 1, "run is already closed").

Closure is a **gate**, not proof of truth. A successfully closed run satisfied the protocol's required fields; whether the work was actually correct is a separate owner judgment.

## Dogfood summary (001–004)

Four dogfood runs exercised Agent OS against delegated work in sibling projects, keeping the core repository frozen.

| Run | Focus | Key lesson |
|-----|-------|------------|
| **001** — todo CLI | End-to-end protocol mechanics | Works; seven artifacts feel heavy for tiny toy tasks |
| **002** — Markdown evidence pack | Medium-scope local CLI | Governance justified; manual evidence capture is friction |
| **003** — local site audit | Medium-risk scope pressure | Kept run bounded; frozen-core discipline validated |
| **004** — JSON config linter | Full evidence stack | All five helpers used in one closure; stack sufficient for v0 |

Dogfood 004 is the capstone: structured evidence entries (`add`, `add-file`, `add-command-output`, `snapshot-git`, `list`) produced a more reviewable record than free-form markdown alone.

See [`dogfood-001-todo-cli.md`](dogfood-001-todo-cli.md), [`dogfood-002-markdown-evidence-pack.md`](dogfood-002-markdown-evidence-pack.md), [`dogfood-003-local-site-audit.md`](dogfood-003-local-site-audit.md), and [`dogfood-004-json-config-linter.md`](dogfood-004-json-config-linter.md).

## Trust model

Agent OS **does not make agents trustworthy by itself**.

What it does:

- structures claims (mission, scope, authority)
- structures evidence (inspectable material tied to claims)
- structures audit (independent verdict)
- structures owner decision (accept or reject)
- structures closure (fail-closed gate on required fields)

What it does not do:

- judge whether evidence is sufficient
- certify that agent claims are true
- replace human review or owner authority

**The owner remains responsible for acceptance.**

## Known limitations

- Evidence helpers register paths and notes; they do not copy, hash, or archive artifacts
- `evidence add-command-output` does not execute commands — the owner must supply output
- `evidence snapshot-git` uses a fixed Git allowlist only (`status`, `diff --stat`); no full diffs or log capture
- No guided fill wizard — required fields must be edited manually in template files
- Ceremony overhead is real for tiny one-shot tasks (see Dogfood 001 threshold lesson)
- Windows transcript noise in command-output capture (documented in Dogfood 004)
- No CI, PyPI publish, or automated release pipeline in this release

## Post-v0 candidates

Parked for future slices (none required for v0.1.0):

- Evidence artifact copy, archive, and hashing
- Stricter Git repo-root validation; git log and full diff capture
- Evidence UX polish and guided fill
- Run profiles (preset mission/scope templates)
- Packaging polish (PyPI), CI, and release automation
- Dogfood on larger multi-step projects

See §8 of [`v0-release-boundary.md`](v0-release-boundary.md).

## Local tag information

This release is tagged locally as `v0.1.0` (annotated) pointing at commit `e20d9199ecaf52856e24bb8f1792881fcd862b2a`.

Release asset documents (`CHANGELOG.md`, this file) may be committed **after** the tag unless the owner authorizes retagging. The tag message is: *Agent OS v0.1.0 local governed-delegation prototype*.

No remote push is part of this release slice.
