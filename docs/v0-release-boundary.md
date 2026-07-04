# Agent OS v0 — release boundary

Formal definition of what Agent OS v0 is, what it includes, what it explicitly excludes, and what must be true before tagging a v0 release.

This document is **boundary and doctrine only**. It does not add CLI commands, validation rules, dependencies, automation, or runtime behavior.

## Baseline commits

Agent OS v0 has a clean committed baseline through:

| Commit | Description |
|--------|-------------|
| `4733237` | Bootstrap Agent OS v0 local foundation |
| `a352501` | Evidence doctrine and Dogfood 003 docs |
| `3013a95` | Evidence add |
| `cd6cc83` | Evidence list |
| `fde905c` | Evidence add-file |
| `6ed674e` | Evidence add-command-output |
| `a0d5b18` | Evidence snapshot-git |
| `1a6abde` | Dogfood 004 evidence stack validation |

The current v0 evidence stack has been validated by Dogfood 004. No additional feature is required before a v0 tag unless the owner explicitly reopens scope.

---

## 1. v0 identity

**Agent OS v0** is a **local filesystem protocol and CLI** for governed agentic delegation.

It structures how a human owner delegates work to fallible coding and research agents by making mission, scope, authority, evidence, audit, owner decision, and closure explicit and inspectable on disk.

Agent OS v0 is **not**:

- a dashboard or UI
- an agent runtime or executor
- an orchestrator or scheduler
- a SaaS product or cloud service
- a benchmark framework
- a trust engine that certifies agent output

The protocol lives in markdown artifacts under `.agent-os/` inside projects that adopt it. The CLI bootstraps workspaces, creates runs from templates, surfaces blocking fields, records audit verdicts, registers evidence, and attempts fail-closed closure.

---

## 2. In v0

The following surface is **accepted and in scope** for Agent OS v0:

### Core package

- Local Python package installable from source (`pip install -e .`)
- Standard library only — no runtime dependencies

### CLI commands

| Command | Purpose |
|---------|---------|
| `init` | Bootstrap `.agent-os/` workspace in a target project |
| `mission` | Create a new governed run from templates |
| `status` | List runs and fields blocking closure |
| `audit` | Record an audit verdict |
| `close` | Attempt fail-closed run closure |
| `evidence add` | Append a structured evidence note (registrar only) |
| `evidence add-file` | Register a file path as evidence (reference only) |
| `evidence add-command-output` | Register a command string and owner-supplied output (no execution) |
| `evidence snapshot-git` | Record read-only Git state via fixed allowlist (`status`, `diff --stat`) |
| `evidence list` | Read-only index of structured evidence entries |

### Workspace and run structure

- Standardized `.agent-os/` workspace layout
- Per-run folders under `.agent-os/runs/<run-id>/`
- `run.json` metadata (status, timestamps)

### Templates

Packaged markdown templates for:

- mission
- preflight
- evidence
- audit
- owner-decision
- closure
- memory-update

### Validation

- Fail-closed closure validation
- Required fields: mission statement, scope, authority, autonomy level or gates, at least one evidence item, audit verdict, owner decision, closure verdict
- Already-closed guard on re-close attempts

### Documentation (`docs/`)

- Thesis, primitives, operating loop, autonomy levels, memory hygiene
- Evidence capture doctrine (`evidence-capture-doctrine-v0.md`)
- Evidence capture boundaries (`evidence-capture-boundaries-v0.md`)
- Dogfood synthesis 001–004
- This release boundary document

### Dogfood evidence

External sibling projects exercised the protocol without polluting core:

- Dogfood 001 — todo CLI
- Dogfood 002 — Markdown evidence pack
- Dogfood 003 — local site audit
- Dogfood 004 — JSON config linter (full evidence stack)

### Tests

- `tests/test_agent_os.py` — unittest suite for CLI, workspace, and validation behavior

---

## 3. Out of v0

The following are **explicitly excluded** from Agent OS v0. They may be considered post-v0 but must not be added under the v0 boundary without an explicit scope reopen:

| Exclusion | Rationale |
|-----------|-----------|
| Automatic agent invocation | Agent OS is protocol, not runtime |
| Orchestration | No job queue, no agent loop |
| Multi-agent scheduling | No coordination layer |
| Dashboards / UI | Local markdown and CLI only |
| SaaS / cloud / API server | Local-first, no hosted service |
| Multi-user / auth / billing | Single-owner local use |
| LLM calls | No summarization, no "good enough?" models |
| Auto-audit | Audit is an explicit owner or reviewer action |
| Auto-close | Closure is explicit and fail-closed |
| Arbitrary command execution | Helpers register evidence; they do not run work |
| Generic shell runner | No wrapped shell session |
| Full artifact archive / copy / hash | Evidence registers paths; does not archive files |
| Automatic evidence capture on close | Capture is deliberate and opt-in |
| Benchmark framework | Not a comparative evaluation platform |
| CI / release automation | Unless separately decided by owner |

---

## 4. Trust model

Agent OS **does not make agents trustworthy by itself**.

What it does:

- **Structures claims** — mission and scope define what was asked and permitted
- **Structures evidence** — helpers register inspectable material tied to claims
- **Structures audit** — an independent verdict weighs evidence against mission
- **Structures owner decision** — the owner accepts or rejects; evidence informs only
- **Structures closure** — a fail-closed gate checks required fields are filled

What it does not do:

- Judge whether evidence is sufficient for acceptance
- Certify that agent claims are true
- Replace human review or owner authority
- Prove that closed runs were correct — only that the ceremony was completed

**Evidence helpers register or narrowly produce evidence; they do not judge sufficiency.**

**The owner remains responsible for acceptance.**

**Closure is a gate, not proof of truth.** A run that closes successfully has satisfied the protocol's required fields. Whether the work was actually correct is a separate judgment the owner and auditor must make from the evidence.

---

## 5. Evidence model

Agent OS v0 provides a layered evidence stack. Each layer captures material; none judges whether closure should succeed.

### Evidence types (v0)

| Type | Mechanism | What it captures |
|------|-----------|------------------|
| **Notes** | `evidence add` | Owner- or agent-supplied text tied to a claim |
| **File references** | `evidence add-file` | Path to an on-disk artifact (no copy, no hash) |
| **Command transcripts** | `evidence add-command-output` | Command string + owner-supplied output file (no execution) |
| **Git snapshots** | `evidence snapshot-git` | Read-only `git status --porcelain` and `git diff --stat` from an explicit invocation |
| **Evidence index** | `evidence list` | Read-only structured list of registered entries |

Free-form content in `evidence.md` remains valid. Structured helpers append typed blocks that `evidence list` can index.

### Capture vs judgment boundary

```
┌──────────────────────┬─────────────────────────────────────────────┐
│ Capture (helpers)    │ Judgment (not helpers)                      │
├──────────────────────┼─────────────────────────────────────────────┤
│ Register notes       │ Whether notes support a claim               │
│ Register file paths  │ Whether files prove success                 │
│ Register transcripts │ Whether tests actually passed               │
│ Snapshot Git state   │ Whether diff scope matches mission          │
│ Index entries        │ Whether evidence is closure-grade           │
│                      │ Audit verdict                               │
│                      │ Owner decision                              │
│                      │ Closure gate (presence, not quality)        │
└──────────────────────┴─────────────────────────────────────────────┘
```

Helpers may reject malformed input (empty blocks, missing paths). They must not infer sufficiency, auto-pass validation, or close runs.

See `docs/evidence-capture-doctrine-v0.md` and `docs/evidence-capture-boundaries-v0.md` for full doctrine.

---

## 6. Dogfood evidence

Four dogfood runs exercised Agent OS v0 against delegated work. Each run kept the core repository frozen and used a sibling project for implementation.

### Dogfood 001 — todo CLI

**What was learned:** Agent OS v0 mechanics work end-to-end (init, mission, status, fail-closed close, audit). The protocol is inspectable and keeps scope tight.

**Friction:** Seven artifacts for a tiny, low-risk capture run felt ceremonially heavy. Manual YAML/frontmatter editing across multiple files cost more than the work itself for this scope.

**Threshold lesson:** Agent OS is probably overkill for one-shot toy tasks where a normal prompt suffices.

See `docs/dogfood-001-todo-cli.md`.

### Dogfood 002 — Markdown evidence pack

**What was learned:** Medium-scope local CLI work (new implementation, tests, fixtures, sample reports) justified governance more than Dogfood 001. Mission and preflight kept boundaries explicit; fail-closed closure prevented premature "done."

**Friction:** Manual terminal evidence capture — command outputs had to be copied into `evidence.md` by hand. Dogfood project was initially created inside core repo path (hygiene lesson: keep dogfood projects as siblings).

**Threshold lesson:** Partially validates the usage threshold for medium-scope work; ceremony tax remains.

See `docs/dogfood-002-markdown-evidence-pack.md`.

### Dogfood 003 — local site audit

**What was learned:** A medium-risk problem (site audit) naturally creates scope pressure toward crawling, HTTP, Lighthouse, dashboards. Agent OS kept the run bounded to local filesystem inspection. Core remained frozen and clean.

**Friction:** Re-close after successful closure returned exit code 1 ("run is already closed") — benign guard behavior, but reports must distinguish "blocked closure" from "already closed."

**Threshold lesson:** Better representative dogfood than 001; validates frozen-core discipline.

See `docs/dogfood-003-local-site-audit.md`.

### Dogfood 004 — JSON config linter

**What was learned:** Full evidence stack validated in one closure. All five helpers (`add`, `add-file`, `add-command-output`, `snapshot-git`, `list`) used together produced a more reviewable evidence record than free-form markdown alone. Audit and closure rested on structured, indexed entries.

**Friction:** Evidence capture still requires deliberate shell/file preparation. No artifact copying, hashing, or archive. Windows transcript noise in command-output capture.

**Threshold lesson:** Evidence stack is sufficient for v0. No additional evidence helper is required before tag.

See `docs/dogfood-004-json-config-linter.md`.

---

## 7. Release readiness checklist

Before tagging Agent OS v0, the following must be true:

- [ ] **Tests pass** — `python -m unittest discover -s tests -v` exits 0
- [ ] **Working tree clean** — no uncommitted changes in core (or only this boundary doc if not yet committed)
- [ ] **No Breezly content** — core repo contains no imported Breezly project material
- [ ] **No root `.agent-os/`** — core repo is protocol source, not a governed project workspace
- [ ] **No dogfood project directory in core** — dogfood implementations live in sibling folders only
- [ ] **README references v0 boundary** — link to this document present
- [ ] **No out-of-scope features present** — nothing from §3 Out of v0 shipped in core
- [ ] **Owner approval** — owner explicitly accepts this boundary and authorizes v0 tag

---

## 8. Post-v0 candidates

The following items are **parked** for post-v0 slices. None are required for v0:

| Candidate | Notes |
|-----------|-------|
| Evidence artifact copy / archive | Register paths today; no copy into run directory |
| Hashing | File integrity not captured in v0 |
| Stricter Git repo-root validation | `snapshot-git` accepts explicit `--repo` |
| Git log capture | Only status and diff-stat in v0 |
| Full diff capture | Only `--stat` in v0; no full hunks |
| Evidence UX polish | Formatting, indexing, readability improvements |
| Guided fill | Wizards for required fields — explicitly out of v0 |
| Run profiles | Preset mission/scope templates for common run types |
| Packaging polish | PyPI publish, version pinning, install UX |
| CI | Automated test runs, release pipelines |
| Public release assets | Changelog, tagged releases, distribution |
| Dogfood on larger multi-step projects | Validate protocol at higher complexity |

---

## 9. Final v0 boundary decision

**Agent OS v0 is ready to be treated as a local governed-delegation prototype** once this release-boundary document is accepted and committed.

The committed baseline through `1a6abde` (Dogfood 004 evidence stack validation) delivers:

- A stdlib-only local CLI for governed run lifecycle
- Fail-closed closure validation
- A complete registrar-only evidence helper stack
- Doctrine and dogfood evidence documenting usage thresholds, friction, and boundaries

**No additional feature is required before a v0 tag**, unless the owner explicitly reopens scope.
