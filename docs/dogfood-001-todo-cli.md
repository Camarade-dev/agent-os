# Dogfood 001 — todo-cli

First Agent OS v0 dogfood run. Captures what worked, what felt heavy, and when the protocol earns its overhead.

## Dogfood project location

Canonical toy project (sibling to the Agent OS core repo):

```
../agent-os-dogfood-todo-cli/
```

Closed run artifacts live under `.agent-os/runs/20260704-001/` in that project. The core `agent-os/` repository must not contain a copy of the toy CLI.

## What was tested

- Bootstrap a governed workspace in an external project (`agent-os init`).
- Open a run from templates (`agent-os mission`).
- Inspect blocking fields before closure (`agent-os status`).
- Fail-closed closure until required artifacts are filled (`agent-os close`).
- Complete the seven-artifact ceremony manually (mission, preflight, evidence, audit, owner decision, closure, memory update).
- Re-run the existing todo-cli unit tests as evidence (5 tests, unchanged).

Mission: govern a protocol capture run against the existing `todo-cli` toy project without modifying Agent OS core or adding CLI features.

## Agent OS commands used

```bash
agent-os init <dogfood-project-path>
agent-os mission <dogfood-project-path>
agent-os status <dogfood-project-path>
agent-os close 20260704-001 <dogfood-project-path>   # blocked, then succeeded
agent-os audit 20260704-001 <dogfood-project-path> --verdict pass
```

## Fail-closed behavior observed

- Pre-completion `close` exited with code 1 and listed nine blocked fields (mission statement, scope, authority, autonomy, evidence, audit verdict, owner decision, closure verdict, and related gaps).
- Closure succeeded only after required artifacts were filled and audit recorded.
- Run status moved to `closed` in `run.json` with a recorded `closed_at` timestamp.

## What worked

- Filesystem-local protocol is inspectable: every gate is a markdown file under `.agent-os/runs/<run-id>/`.
- `status` clearly surfaces what blocks closure before an owner wastes time on a premature close.
- Templates give a consistent structure for mission, authority, evidence, and closure without a UI or server.
- The protocol kept scope tight: no Agent OS core edits, no new todo-cli features, no commits during the run.
- Existing project tests served as concrete evidence without extra instrumentation.

## What felt too heavy

- Seven artifacts for a tiny, low-risk capture run (copy a toy project, run CLI commands, run unit tests).
- Manual YAML/frontmatter editing across multiple files for work that a single well-scoped prompt could complete in minutes.
- `memory-update.md` remained mostly placeholder — useful as a discipline reminder, but overhead for a one-off dogfood.
- No guided `fill` helper in v0: the owner/agent must know which fields map to which templates.

## When Agent OS is useful

- Governed delegation where **mission, authority, evidence, audit, and closure** must be explicit and reviewable.
- Work with real scope risk: production changes, cross-cutting refactors, security-sensitive edits, or multi-step agent handoffs.
- Runs that need a durable record of what was asked, permitted, done, verified, and accepted.
- Situations where fail-closed closure prevents “looks done” from masquerading as actually done.

## When Agent OS is probably overkill

- Tiny one-shot tasks where a normal prompt and a quick sanity check are enough.
- Exploratory spikes with no audit trail requirement.
- Single-file edits, doc typos, or toy projects with no governance stakes.
- Any task where filling seven markdown artifacts costs more than the work itself.

## Outcome

Run `20260704-001` closed as `CLOSED_SUCCESS`. Agent OS v0 mechanics validated; protocol left unchanged pending this synthesis.

## Residual note

Post-dogfood cleanup removed a stray untracked `todo-cli/` copy from inside the Agent OS core repo. The sibling `agent-os-dogfood-todo-cli/` folder remains the canonical dogfood project.
