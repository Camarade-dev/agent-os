# Evidence capture doctrine (v0)

Design note for Agent OS v0. Defines what counts as acceptable evidence and how evidence should be captured without turning Agent OS into an orchestrator or runtime.

This document is **doctrine only**. It does not add CLI commands, validation rules, dependencies, or automation.

## 1. Purpose

Evidence exists in Agent OS to:

- **Support audit** — give an independent reviewer inspectable material to compare against mission, scope, and success criteria.
- **Make closure trustworthy** — closure is not “the agent said done”; it is a governed disposition backed by proof.
- **Preserve owner authority** — the owner decides acceptance; evidence informs that decision but does not replace it.
- **Prevent self-certification** — agents must not close runs on prose alone when direct artifacts or observations could falsify their claims.

Evidence is the third separation-of-concerns primitive: what was **asked** (mission), what was **permitted** (authority), what was **done** (evidence), what was **verified** (audit), what the owner **accepts** (owner decision).

## 2. Evidence definition

**Evidence** is an inspectable artifact or observation that supports or falsifies a claim about the run.

A claim might be: “tests pass,” “scope was not exceeded,” “the CLI produces the expected report,” or “no core files were modified.” Evidence ties a specific claim to something a reviewer can inspect — not merely to agent intent or confidence.

Evidence may live in `evidence.md`, referenced files on disk, or clearly cited paths. It must be **reviewable after the fact** without re-running the agent’s hidden reasoning.

## 3. Acceptable evidence types

The following are acceptable in v0 when tied to a claim:

| Type | Examples | Notes |
|------|----------|-------|
| **Command outputs** | Exit code, stdout/stderr excerpts, `pytest -v` summary | Prefer summarized output; full logs by path reference |
| **Test results** | Unittest/pytest pass counts, failure traces | Strong when command + output + path are recorded |
| **Git diff / git status** | `git diff --stat`, `git status -sb`, focused hunks | Supports scope and “what changed” claims |
| **Generated files** | `report.json`, build artifacts, sample outputs | Cite path; reviewer can open the file |
| **Reports** | Markdown or JSON reports produced by the work under test | Especially useful for medium-scope runs |
| **Screenshots** | UI or terminal captures | Use when visual state matters; store locally or cite path |
| **Human owner observations** | “I ran the CLI manually and verified …” | Valid; distinguish from agent-generated claims |
| **Agent final reports** | Structured run summary from the executing agent | Acceptable as **one** evidence item if paired with artifacts where they exist |
| **External links** | PR URLs, issue links, CI run pages | Use with caution: link rot and access control weaken audit |
| **Timestamps and paths** | When a command ran, cwd, absolute or repo-relative paths | Strengthen reproducibility and post-hoc review |

Unacceptable as sole evidence: vague narrative, unchecked assertions, or “trust me” without inspectable backing.

## 4. Evidence quality levels

Use these levels when writing or reviewing `evidence.md`. Closure should aim for **acceptable** or better; audit should prefer **strong** or **closure-grade** for mission-critical claims.

| Level | Description | Example |
|-------|-------------|---------|
| **Weak** | Unchecked agent claim | “All tests pass” with no command or output |
| **Acceptable** | Pasted command output or a generated artifact on disk | `python -m unittest discover -s tests -v` output pasted; path to `report.json` |
| **Strong** | Reproducible command + output + file path | Command, cwd, timestamp, exit code, summarized output, and path to artifact |
| **Closure-grade** | Strong evidence explicitly tied to mission success criteria and audit verdict | “Success criterion: 6 tests pass” → command, output showing 6 passed, path to test file, matches audit pass |

Quality is not a separate validation gate in v0; it is a **discipline** for owners, agents, and auditors.

## 5. Evidence capture rules

Practical v0 rules:

1. **Local-first when possible** — prefer filesystem artifacts and pasted terminal output over external-only links.
2. **Tied to a claim** — each evidence block should state what claim it supports (e.g., “Scope: no Agent OS core edits”).
3. **Command, output, path, timestamp when relevant** — enough context for a reviewer to reproduce or spot-check.
4. **Facts vs interpretation** — label observations (“exit code 0”) separately from inference (“therefore feature works”).
5. **No huge logs inline** — summarize; point to log file path for full detail.
6. **Do not rely only on agent prose when a direct artifact exists** — if `git diff` or test output exists, capture it.
7. **One run, one evidence trail** — avoid mixing evidence from parallel shells or re-close attempts without labeling which attempt each block belongs to (see Dogfood 003).

Recommended structure in `evidence.md` (aligned with the template):

```markdown
## Claim: <what this supports>

**Observed (fact):**
- Command: `...`
- Cwd: `...`
- Timestamp: `...`
- Exit code: ...
- Output (summary): ...

**Artifact path:** `path/to/file`

**Interpretation (optional):** ...
```

## 6. What evidence is not

Evidence is **not**:

- a **vibe** — confidence, tone, or “looks good” without inspectable backing;
- a generic **“done”** statement;
- **hidden chain of thought** — reasoning that cannot be reviewed;
- an **unverifiable agent claim** — assertions with no path to falsification;
- a **replacement for owner decision** — evidence informs; owner decides;
- a **replacement for audit** — audit independently weighs evidence against mission and scope.

Closure validation in v0 only checks that evidence **body is present** (non-placeholder). Quality and sufficiency remain human and audit responsibilities.

## 7. Manual-first doctrine

Agent OS v0 keeps evidence capture **manual** on purpose:

- **Avoids premature orchestration** — auto-capture would imply Agent OS executes or wraps the agent runtime.
- **Keeps the owner aware** — copying outputs and choosing what to accept forces conscious trust boundaries.
- **Avoids over-automation of trust** — helpers can register artifacts; they must not auto-pass audit or closure.
- **Preserves protocol vs runtime** — Agent OS structures governance; external agents and shells perform work.

Manual capture is friction (Dogfood 002). That friction is an acceptable v0 tax compared to building the wrong abstraction.

## 8. Parked feature pressure

Do **not** implement in v0. Document for later evaluation:

| Possible helper | Role if added later |
|-----------------|---------------------|
| `agent-os evidence add` | Append a structured evidence block to `evidence.md` |
| Command transcript capture | Record command + cwd + timestamp + summarized output |
| Git diff snapshot capture | Attach `git status` / `git diff --stat` to a claim |
| Test output capture | Run or ingest test command output into evidence |
| Artifact registration | Register path + hash + claim without moving files |
| Evidence index generation | Summarize evidence blocks for audit review |

Any future helper must **register** evidence, not **replace** judgment, audit, or owner decision. Helpers must not invoke LLMs, call cloud services, or execute agent work on behalf of the owner without explicit scope.

## 9. Dogfood lessons

### Dogfood 001 — todo-cli

- **Ceremony too heavy for tiny tasks** — seven artifacts for a copy-and-test capture run cost more than the work itself.
- **Existing tests as evidence worked** — concrete test output without new instrumentation satisfied closure.
- **Protocol still valuable for scope** — kept Agent OS core untouched and made fail-closed behavior visible.

**Evidence takeaway:** for low-risk runs, minimal but **acceptable** evidence (test command + output) is enough; do not inflate ceremony in the evidence section.

### Dogfood 002 — markdown evidence pack

- **Evidence trail useful** — mission, scope, and generated reports gave audit something real to review.
- **Manual terminal capture friction** — copying command output into `evidence.md` by hand was the main tax.
- **Medium scope justified more evidence** — generated files (`report.md`, `report.json`) plus test output matched closure-grade expectations better than prose alone.

**Evidence takeaway:** prefer generated artifacts and summarized command output; park automation until doctrine is stable.

### Dogfood 003 — (synthesis)

- **Evidence and closure useful** — structured final reports and explicit success-criteria mapping helped trustworthy close.
- **Parallel shell / re-close noise** — multiple terminal sessions or repeated `close` attempts can produce duplicate or conflicting evidence blocks if not labeled by attempt or time.
- **Reporting clarity matters** — final agent reports are useful evidence items but should reference primary artifacts, not substitute for them.

**Evidence takeaway:** one coherent evidence narrative per run; label attempt/session when re-running commands or re-attempting closure.

## 10. v0 decision

**Evidence capture remains manual in v0.**

Owners and agents fill `evidence.md` by hand (or by editing markdown directly). Agent OS validates presence, not quality. Audit and owner decision judge sufficiency.

Agent OS **may** later add helper commands that register evidence blocks, snapshots, or artifact paths. Those helpers must:

- remain local-first and stdlib-compatible unless explicitly scoped otherwise;
- register evidence, not auto-certify success;
- not replace audit, owner decision, or fail-closed closure discipline;
- not turn Agent OS into an orchestrator, runtime, or agent executor.

Until then, follow this doctrine when writing evidence: tie claims to inspectable artifacts, prefer reproducible command output over prose, and keep the distinction between **protocol** (Agent OS) and **runtime** (external agent + shell).

## Related docs

- `docs/primitives.md` — artifact roles and workspace layout
- `docs/operating-loop.md` — where evidence fits in the loop
- `docs/dogfood-001-todo-cli.md` — first dogfood synthesis
- `docs/dogfood-002-markdown-evidence-pack.md` — second dogfood synthesis
