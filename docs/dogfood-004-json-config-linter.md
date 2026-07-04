# Dogfood 004 — JSON config linter

Formal synthesis for the fourth Agent OS v0 dogfood run. This run tested the full evidence helper stack against a medium-scope local JSON config linter CLI while keeping the Agent OS core repository frozen.

## Project and run

Project name:

```
agent-os-dogfood-json-config-linter
```

Canonical dogfood project location (sibling of the Agent OS core repo):

```
../agent-os-dogfood-json-config-linter/
```

Run ID:

```
20260704-001-dogfood-004-json-config-linter
```

Closed run artifacts live under `.agent-os/runs/20260704-001-dogfood-004-json-config-linter/` in that project. The core `agent-os/` repository was not the implementation target and did not receive a `.agent-os/` workspace at its root.

Agent OS core was frozen at commit:

```
a0d5b18
```

Final dogfood status:

```
DOGFOOD_CLOSED_SUCCESS
```

## What was built

The dogfood project implements a local Python stdlib-only JSON config linter (`json_config_linter.py`).

The CLI:

- recursively scans a folder for `.json` files;
- detects invalid JSON syntax;
- detects top-level values that are not JSON objects;
- detects empty objects (`{}`);
- detects duplicate keys (via `json.loads` with `object_pairs_hook`);
- writes human-readable `report.md` and machine-readable `report.json`.

The project includes README, unittest fixtures under `tests/fixtures/`, and **8 passing tests** covering recursive discovery, valid object acceptance, invalid JSON, non-object top-level values, empty objects, duplicate keys, both report outputs, and non-zero exit on an invalid input folder.

A sample scan of `tests/fixtures` produced 7 files with 5 invalid files and 6 total issues.

## What Agent OS tested

Dogfood 004 exercised Agent OS v0 as a frozen protocol on delegated medium-scope work:

- **Fail-closed closure before artifacts were filled** — an early `agent-os close` attempt blocked with nine missing required fields before mission, preflight, evidence, audit, owner decision, and closure artifacts were complete.
- **Full evidence stack usage** — all five evidence helpers were used: `evidence add`, `evidence add-file`, `evidence add-command-output`, `evidence snapshot-git`, and `evidence list`.
- **Audit / owner / closure chain** — independent audit (`pass`), owner decision, and closure (`CLOSED_SUCCESS`) completed only after structured evidence was registered.
- **Frozen core preservation** — Agent OS core `git status` and `git diff` remained clean; no CLI or validation behavior was changed in core.
- **Scope boundary enforcement** — mission and preflight kept the work on stdlib-only local JSON linting; schema validation, auto-fix, plugins, YAML/TOML/JSON5, web, UI, orchestration, and Agent OS core edits stayed out of scope.

The run did not test web crawling, HTTP fetching, schema validation, auto-fix, dashboards, plugins, orchestration, cloud features, SaaS behavior, APIs, LLM calls, or guided fill.

## Evidence stack assessment

Dogfood 004 is the first dogfood run to exercise the complete v0 evidence helper stack in one closure. How each helper was used:

| Helper | Role in Dogfood 004 |
|--------|---------------------|
| `evidence add` | Registered a scope/implementation note: stdlib-only JSON linter, duplicate keys via `object_pairs_hook`, Agent OS core frozen at `a0d5b18`, and explicit out-of-scope boundaries (no YAML/TOML/JSON5/schema/auto-fix/plugins). |
| `evidence add-file` | Registered `sample-output/report.md` as the human-readable sample scan report from `tests/fixtures`. |
| `evidence add-command-output` | Captured the unit test transcript (`python -m unittest discover -s tests -v`) into `test-output.txt` and registered it as structured evidence (8 tests passed). |
| `evidence snapshot-git` | Recorded explicit dogfood-project Git state before closure: branch `master`, `git status --porcelain`, and `git diff --stat` showing uncommitted implementation files. |
| `evidence list` | Provided a structured evidence index (four typed entries: note, file, command-output, git-snapshot) for audit and closure review before the run closed. |

Compared with earlier dogfoods that relied primarily on free-form markdown in `evidence.md`, the structured entries made claims, paths, and provenance easier to scan during audit.

## What improved compared to earlier dogfoods

- **Less free-form evidence capture** — typed evidence entries (`note`, `file`, `command-output`, `git-snapshot`) replaced hand-pasted prose as the primary proof surface.
- **Audit became easier** — the auditor could verify scope, test output, sample report, and Git state from discrete indexed entries instead of hunting through a single markdown blob.
- **Git state became explicit** — `evidence snapshot-git` made uncommitted dogfood work visible without inferring state from narrative evidence.
- **Closure became more trustworthy** — fail-closed gates plus structured evidence meant closure rested on registered artifacts, not on whether someone remembered to paste a transcript.
- **Still manual, but less fragile than raw markdown only** — helpers are registrar-only and require deliberate shell/file preparation, yet the resulting record is more consistent and reviewable than Dogfood 001–003 evidence capture alone.

## Remaining friction

- **Evidence capture still requires deliberate shell/file preparation** — transcripts must be written to a file (or piped) before `add-command-output`; there is no automatic capture on command execution.
- **Dogfood project was not committed by design** — the Git snapshot correctly shows untracked/uncommitted files; no commit or push was requested for the sibling project.
- **Only `report.md` was registered, not `report.json`** — the machine-readable report was generated and tested but not separately registered via `add-file`; audit relied on test coverage and the markdown sample.
- **Windows output encoding can affect transcripts** — PowerShell capture included a UTF-8 BOM and stderr routing noise (`NativeCommandError`) in the test transcript; the tests still passed, but the stored output is noisier than a clean POSIX capture.
- **No artifact copying, hashing, or full archive yet** — evidence helpers register paths and inline snapshots; they do not copy files into the run directory, hash contents, or produce a full evidence archive.

## Feature pressure parked

The following feature pressure is explicitly parked. None should be implemented from Dogfood 004 alone:

- artifact copying into run directories;
- content hashing of evidence files;
- full diff capture beyond `git diff --stat`;
- git log capture;
- automatic evidence capture on close;
- auto-audit;
- dashboards;
- orchestration.

Each would change Agent OS from a minimal local registrar protocol toward runtime behavior, product surface, or coordination machinery and requires a separate design decision.

## Conclusion

Dogfood 004 validates the current Agent OS v0 evidence stack as **useful enough for medium-scope delegated work**. The JSON config linter had natural implementation pressure (schema validation, auto-fix, multi-format support, plugins) and meaningful evidence needs (tests, reports, Git state). Agent OS kept the work bounded, produced a reviewable structured evidence record, and closed under explicit gates without modifying core behavior.

**No new Agent OS feature should be added before synthesizing the v0 release boundary.** Residual friction (manual capture, partial file registration, Windows transcript noise, no hashing/archive) is documented debt, not authorization to expand v0 inside this synthesis.

## Agent OS commands used

```bash
agent-os init ../agent-os-dogfood-json-config-linter
agent-os mission ../agent-os-dogfood-json-config-linter --run-id 20260704-001-dogfood-004-json-config-linter
agent-os status ../agent-os-dogfood-json-config-linter
agent-os close 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter   # blocked, then succeeded
agent-os evidence add 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter --note "..."
agent-os evidence add-file 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter sample-output/report.md --note "..."
agent-os evidence add-command-output 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter --command "python -m unittest discover -s tests -v" --output-file .agent-os/runs/20260704-001-dogfood-004-json-config-linter/test-output.txt --note "..."
agent-os evidence snapshot-git 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter --note "..."
agent-os evidence list 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter
agent-os audit 20260704-001-dogfood-004-json-config-linter ../agent-os-dogfood-json-config-linter --verdict pass
```

## Outcome

Run `20260704-001-dogfood-004-json-config-linter` closed as `CLOSED_SUCCESS` / `DOGFOOD_CLOSED_SUCCESS`. Agent OS v0 full evidence stack validated on a medium-scope local CLI; protocol and core left unchanged except for this synthesis doc and README reference.
