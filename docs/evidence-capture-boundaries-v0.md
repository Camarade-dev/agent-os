# Evidence capture boundaries (v0)

Design note for Agent OS v0. Defines what **future** evidence-capture helpers may and may not do, and where capture ends and execution begins.

This document is **design only**. It does not add CLI commands, validation rules, dependencies, automation, or runtime behavior.

Companion: `docs/evidence-capture-doctrine-v0.md` (what counts as acceptable evidence and how to capture it manually today).

## 1. What future evidence helpers may do

Future helpers are **registrars**: they append structured, inspectable material to a run's evidence trail. They reduce friction from manual copy-paste; they do not judge sufficiency or certify success.

Helpers **may**:

| Capability | Description | Example |
|------------|-------------|---------|
| **Append a manually supplied evidence block** | Owner or agent provides text; helper formats and appends to `evidence.md` with timestamp and optional claim label | `--note "pytest: 6 passed"` |
| **Register a file path as evidence** | Record repo-relative or absolute path, optional hash, and claim without moving or modifying the file | `add-file path/to/report.json` |
| **Record a pasted command/output pair** | Accept command string and output (inline or from a file path the owner already created) | `--command "python -m unittest …" --output-file out.txt` |
| **Snapshot git state when explicitly invoked** | Run `git status` / `git diff --stat` (or similar) **only** when the owner calls a dedicated snapshot subcommand — never on every close or status check | `evidence snapshot-git <run-id>` |
| **Index evidence already provided** | Summarize existing blocks in `evidence.md` for audit review (list, headings, paths cited) | `evidence list <run-id>` |
| **Attach metadata** | Cwd, timestamp, run-id, attempt label, exit code when supplied by the owner | Frontmatter or block headers |
| **Validate format, not truth** | Reject empty blocks or malformed paths; do **not** infer whether evidence supports closure | Schema checks only |

All helper output remains **evidence candidate** material. The owner still chooses what to invoke and what to accept.

## 2. What future evidence helpers must not do

Helpers must not cross into orchestration, judgment, or trust automation.

Helpers **must not**:

| Prohibition | Rationale |
|-------------|-----------|
| **Execute arbitrary agent tasks** | Agent OS is protocol, not runtime; work happens in external shells and agents |
| **Run tests, builds, or audits on behalf of the owner without explicit, scoped invocation** | Even `snapshot-git` is opt-in; no background command runner |
| **Decide whether evidence is sufficient** | Sufficiency is audit + owner responsibility |
| **Replace audit** | Audit independently weighs evidence against mission and scope |
| **Replace owner decision** | Owner accepts or rejects; evidence informs only |
| **Silently trust agent prose** | Agent summaries may be registered; they are not auto-promoted to verified fact |
| **Automatically close runs** | Closure stays explicit, fail-closed, and separate from capture |
| **Auto-pass validation** | Presence checks in v0 remain unchanged; helpers do not flip placeholders to "done" by inference |
| **Turn Agent OS into a runtime/orchestrator** | No job queue, no agent loop, no wrapped shell session |
| **Invoke LLMs** | No summarization, no "is this good enough?" models |
| **Call cloud services** | Local-first; no upload, SaaS, or API dependencies |
| **Execute guided fill** | No wizards that decide what evidence the run needs |
| **Modify mission, scope, authority, or audit artifacts** | Evidence helpers touch evidence (and optional local index files under the run), nothing else |

If a proposed helper would **produce** evidence by running work the owner did not explicitly request in that command, it belongs outside this boundary slice.

## 3. Boundary between capture and execution

Five activities stay separate. Future helpers sit only in the first column.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Activity              │ Who / what          │ Helper role               │
├───────────────────────┼─────────────────────┼───────────────────────────┤
│ Capturing evidence    │ Owner, agent, shell │ MAY assist registration │
│ Running commands      │ External shell      │ MUST NOT (except explicit │
│                       │                     │  opt-in snapshots)        │
│ Interpreting evidence │ Auditor, owner      │ MUST NOT                  │
│ Auditing evidence     │ `agent-os audit`    │ MUST NOT                  │
│ Deciding closure      │ Owner + fail-closed │ MUST NOT                  │
│                       │ `agent-os close`    │                           │
└─────────────────────────────────────────────────────────────────────────┘
```

**Capturing** — Recording what was observed: command text, output excerpt, file path, timestamp, claim label. The owner or agent supplies content; the helper formats and appends.

**Running commands to produce evidence** — Executing `pytest`, `git diff`, builds, or crawlers in the project under test. That is **runtime work**, done in the owner's or agent's shell. A helper may record output the owner **already** captured to a file; it may run **only** narrowly scoped read-only snapshots when the owner explicitly invokes a snapshot subcommand (e.g. `git status`). It must not chain commands, retry failures, or "helpfully" run tests during `close`.

**Interpreting** — Drawing conclusions ("therefore feature works"). Belongs in optional interpretation lines inside evidence blocks, written by humans; not in helper logic.

**Auditing** — Independent comparison of evidence to mission and scope via `agent-os audit`. Unchanged by capture helpers.

**Deciding closure** — Owner decision + `agent-os close` with existing fail-closed validation. Helpers do not pre-approve, auto-fill audit, or skip gates.

**Line rule:** If the operation **changes world state** beyond appending to evidence (or writing a helper-local index), it is execution, not capture.

## 4. Safety and trust model

| Principle | Meaning |
|-----------|---------|
| **Helper output is evidence candidate, not truth** | Appended blocks are inspectable claims; reviewers can falsify them |
| **Owner remains responsible** | Owner chooses what to register, what to paste, and what to accept |
| **Audit remains separate** | `agent-os audit` is an explicit step; helpers do not emit audit verdicts |
| **Closure remains fail-closed** | `agent-os close` still requires all artifacts; helpers do not bypass missing fields |
| **No silent promotion** | Registering agent prose does not mark it verified; label source (owner / agent / snapshot) |
| **Reproducibility over convenience** | Prefer command + path + timestamp in registered blocks so audit can spot-check |
| **Local-first** | Artifacts stay on disk; no mandatory cloud or third-party trust |

Trust boundaries match the operating loop: mission → authority → **external execution** → evidence → audit → owner decision → closure. Helpers may shorten the path from shell to `evidence.md`; they must not collapse audit or closure into capture.

## 5. Minimal future command shape (design only)

Illustrative forms for a possible future slice. **Not implemented in v0.**

```bash
# Append a structured note block (owner-supplied text)
agent-os evidence add <run-id> [PATH] --note "..."

# Register an existing file path (+ optional claim)
agent-os evidence add-file <run-id> [PATH] path/to/file [--claim "..."]

# Record command string + output from a file the owner already wrote
agent-os evidence add-command-output <run-id> [PATH] \
  --command "python -m unittest discover -s tests -v" \
  --output-file /tmp/test-out.txt

# List / index blocks already in evidence.md (read-only)
agent-os evidence list <run-id> [PATH]

# Optional explicit snapshot (owner-invoked only; not automatic)
agent-os evidence snapshot-git <run-id> [PATH] [--stat]
```

Design constraints for any implementation:

- `[PATH]` defaults to cwd workspace (same pattern as `audit` / `close`).
- Subcommands append to `evidence.md` (or a documented sibling index); they do not edit other run artifacts.
- `--output-file` reads existing files; it does not run `--command` to create them.
- `snapshot-git` is the only helper that may invoke git, and only when called explicitly.
- Stdlib-only unless a later scoped decision says otherwise.

## 6. v0 implementation status

**`agent-os evidence add` is implemented** as the first minimal bounded helper. It is **registrar-only**: it appends a structured block to `evidence.md` with timestamp, type (default `note`), optional path reference, and claim text. It does not copy files, run commands, judge sufficiency, modify audit/owner-decision/closure artifacts, or auto-close runs.

**`agent-os evidence list` is implemented** as a read-only index helper. It reads `evidence.md` and prints structured entries previously appended by `evidence add`, `evidence add-file`, `evidence add-command-output`, or `evidence snapshot-git` (timestamp, type, optional path, optional command, claim preview, and for git-snapshot entries repo path and branch/head when available). It does not modify any run artifacts or change validation behavior.

**`agent-os evidence add-file` is implemented** as a **reference-only** registrar. It records an existing local file path in `evidence.md` with timestamp, type `file`, path, and claim text. It verifies the path exists but does **not** copy, hash, inspect, parse, or mutate the referenced file. It does not modify audit/owner-decision/closure artifacts or auto-close runs.

**`agent-os evidence add-command-output` is implemented** as **owner-supplied transcript registration only**. It records a declared command string and reads an existing output file (text) into a structured `command-output` block in `evidence.md`, with an 8 KB embedded excerpt limit when the file is larger. It does **not** execute `--command`, validate pass/fail, parse output, or mutate the referenced output file. It does not modify audit/owner-decision/closure artifacts or auto-close runs.

**`agent-os evidence snapshot-git` is implemented** as a **narrow, explicit, read-only Git exception**. When the owner invokes it, Agent OS runs only a fixed allowlist of read-only `git` commands (`rev-parse`, `branch --show-current`, `status --porcelain`, and optionally `diff --stat`) via `subprocess` with `shell=False`. No user-provided command strings are executed. It appends a structured `git-snapshot` block to `evidence.md` with repo path, branch, short HEAD, status output, and optional diff stat. It does **not** run `git add`, `commit`, `push`, `pull`, `checkout`, `reset`, `clean`, or any other mutating Git operation. It is **not** arbitrary command execution. It does not modify audit/owner-decision/closure artifacts, run status, or auto-close runs.

Other helpers listed in section 5 remain **not implemented**.

In v0:

- Evidence capture may be **manual** (edit `evidence.md` directly) or via `agent-os evidence add`, `agent-os evidence add-file`, `agent-os evidence add-command-output`, or `agent-os evidence snapshot-git`.
- Validation checks **presence** of evidence body, not quality or sufficiency.
- Audit, owner decision, and closure behavior are **unchanged**.

Before implementing additional evidence helpers, re-read this note and `docs/evidence-capture-doctrine-v0.md`. Any slice that runs arbitrary commands, auto-closes runs, or replaces audit/owner judgment is out of scope.

## Related docs

- `docs/evidence-capture-doctrine-v0.md` — acceptable evidence types and manual capture rules
- `docs/primitives.md` — `evidence.md` artifact role
- `docs/operating-loop.md` — where evidence fits in the loop
- `docs/dogfood-002-markdown-evidence-pack.md` — manual terminal capture friction
- `docs/dogfood-003-local-site-audit.md` — evidence trail and re-close labeling
