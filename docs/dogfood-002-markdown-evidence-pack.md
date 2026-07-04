# Dogfood 002 — markdown evidence pack

Second Agent OS v0 dogfood run. Captures a medium-scope local CLI build under governance, repo-placement hygiene, and whether the protocol still earns its overhead at slightly higher scope than Dogfood 001.

## Dogfood project location

Canonical dogfood project (sibling to the Agent OS core repo):

```
../agent-os-dogfood-markdown-evidence-pack/
```

Closed run artifacts live under `.agent-os/runs/20260704-001-dogfood-002-md-evidence-pack/` in that project. The core `agent-os/` repository must not contain a copy of the dogfood implementation.

Post-dogfood cleanup moved the project out of an in-core path (`agent-os/agent-os-dogfood-markdown-evidence-pack/`) to preserve core repo hygiene.

## Run ID

`20260704-001-dogfood-002-md-evidence-pack`

## What was tested

- Bootstrap a governed workspace in an external project (`agent-os init`).
- Open a run from templates with an explicit run ID (`agent-os mission --run-id ...`).
- Inspect blocking fields before closure (`agent-os status`).
- Fail-closed closure until required artifacts are filled (`agent-os close`).
- Complete the seven-artifact ceremony manually (mission, preflight, evidence, audit, owner decision, closure, memory update).
- Implement a local Markdown evidence-pack CLI (`md_evidence_pack.py`) under stdlib-only, local-filesystem constraints.
- Re-run the dogfood unit tests as evidence (6 tests).
- Generate sample `report.md` and `report.json` from fixture inputs.

Mission: govern a medium-scope local CLI that scans Markdown folders and writes human- and machine-readable evidence reports, without modifying Agent OS core or adding CLI features.

## Implementation summary

`md_evidence_pack.py` provides a `scan` command that:

- recursively discovers `.md` files under an input folder;
- extracts the first Markdown H1 title per file;
- counts `TODO` and `FIXME` occurrences (uppercase word-boundary matching);
- detects broken local Markdown links relative to each source file;
- writes `report.md` and `report.json` to an output directory.

The project includes README, unittest coverage, and fixture inputs under `tests/fixtures/input/`. Implementation uses Python standard library only; no network, UI, database, or LLM dependencies.

## Fail-closed behavior observed

- Pre-completion `close` exited with code 1 and listed nine blocked fields (mission statement, scope, authority, autonomy, evidence, audit verdict, owner decision, closure verdict, and related gaps).
- Closure succeeded only after required artifacts were filled and audit recorded.
- Run status moved to `closed` in `run.json` with a recorded `closed_at` timestamp.

## What Agent OS helped with

- Kept scope explicit: mission and preflight artifacts documented in-scope vs out-of-scope boundaries before implementation.
- `status` surfaced unfilled required fields before a premature close attempt.
- Fail-closed closure prevented marking the run done while artifacts were still placeholders.
- Filesystem-local artifacts gave a reviewable record of authority, evidence, audit, and owner decision without a UI or server.
- The protocol resisted scope creep toward HTTP, UI, scoring, plugins, or Agent OS core edits.

## Friction observed

- Seven artifacts for a contained CLI still feel heavy relative to the implementation work.
- Manual YAML/frontmatter editing across multiple markdown files remains the main ceremony cost.
- **Manual terminal evidence capture** was a friction point: command outputs had to be copied into `evidence.md` by hand. Do not implement evidence-capture automation yet; only document this as parked friction.
- The dogfood project was initially created inside the Agent OS core repo path, which polluted core hygiene until moved to a sibling folder.
- `memory-update.md` remained mostly placeholder for this neutral dogfood.

## Usage threshold validated?

**Partially yes, with caveats.**

Compared to Dogfood 001, this run exercised a real medium-scope implementation (new CLI, tests, fixtures, sample reports) where mission, authority, evidence, and closure matter more than a copy-and-test exercise. Agent OS helped keep boundaries tight and produced a durable closure record.

The protocol still feels heavy for the artifact count alone. The overhead is more justified here than for a toy capture run, but manual evidence capture and multi-file ceremony remain the main tax. A second dogfood does not yet prove Agent OS is essential for every medium-scope task — it shows the protocol can govern one without scope creep.

## Feature pressure explicitly parked

Do **not** implement yet:

- automated terminal/command-output evidence capture;
- guided `fill` helpers for run artifacts;
- HTML or UI reports for the evidence pack;
- web crawling, HTTP requests, scoring, ranking, or benchmark behavior;
- plugins, cloud, multi-user, auth, or LLM summarization;
- Agent OS core changes driven by this dogfood.

Residual implementation debt (acceptable for this slice):

- Markdown link parsing is intentionally simple and not full CommonMark.
- TODO/FIXME matching is uppercase word-boundary only.
- No quiet or verbose CLI modes.

## Agent OS commands used

```bash
agent-os init <dogfood-project-path>
agent-os mission <dogfood-project-path> --run-id 20260704-001-dogfood-002-md-evidence-pack
agent-os status <dogfood-project-path>
agent-os close 20260704-001-dogfood-002-md-evidence-pack <dogfood-project-path>   # blocked, then succeeded
agent-os audit 20260704-001-dogfood-002-md-evidence-pack <dogfood-project-path> --verdict pass
```

## Outcome

Run `20260704-001-dogfood-002-md-evidence-pack` closed as `CLOSED_SUCCESS`. Agent OS v0 mechanics validated on a medium-scope local CLI; protocol and core left unchanged except for this synthesis doc and README reference.

## Residual note

Post-dogfood cleanup moved `agent-os-dogfood-markdown-evidence-pack/` out of the Agent OS core repo to `../agent-os-dogfood-markdown-evidence-pack/`. Historical paths inside the closed run's `evidence.md` still reference the in-core location from the original run; that is expected archival evidence, not the canonical project location.
