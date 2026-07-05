# Agent OS

**v0.1.0** — local governed-delegation prototype · [release notes](docs/release-notes-v0.1.0.md) · [why Agent OS](docs/why-agent-os.md)

**Live static demo:** https://camarade-dev.github.io/agent-os-demo-governed-agent-chat/ — see how Agent OS wraps a familiar coding-agent chat with mission, scope, evidence, audit, owner decision, and closure.

Agent OS is a **local filesystem protocol and CLI** for governed delegation to fallible coding and research agents. It is not a dashboard, SaaS, runtime, orchestrator, benchmark, or agent panel.

## What problem it solves

Coding and research agents are useful but fallible. Ad-hoc prompts and chat threads do not reliably preserve mission, authority, evidence, audit, owner decision, or closure. Agent OS structures those concerns as inspectable markdown artifacts so delegation stays bounded and reviewable. It does **not** make agents reliable by itself, execute agents, or replace owner judgment.

## What is in v0.1.0

- **CLI** (`init`, `mission`, `status`, `audit`, `close`) plus registrar-only **evidence** helpers (`add`, `add-file`, `add-command-output`, `snapshot-git`, `list`)
- **Templates** for mission, scope, authority, autonomy, evidence, audit, owner decision, closure, and memory update; plus planning artifact contracts under `agent_os/templates/planning/` (doctrine extension — not v0 CLI)
- **Fail-closed closure** — runs cannot close until required fields are filled
- **Stdlib-only Python package** — install from source, Python 3.10+, no runtime dependencies
- **Documentation** — protocol primitives, operating loop, evidence doctrine, dogfood examples

## What is not included

Agent OS v0.1.0 is **not**: a UI or dashboard, an agent executor or orchestrator, a cloud service or API, multi-user auth, billing, benchmarks, LLM calls, auto-audit, or auto-close. See [`docs/v0-release-boundary.md`](docs/v0-release-boundary.md) for the formal boundary.

## Who it is for

Owners who delegate non-trivial work to agents and need **governed handoffs** — real scope risk, reviewable artifacts, and closure that waits on explicit fields, not on the agent stopping. Skip it for one-shot prompts where structure would be overhead.

## Try it locally

```bash
git clone https://github.com/Camarade-dev/agent-os.git
cd agent-os
pip install -e .
agent-os init .
agent-os mission .
agent-os status .
```

Fill run artifacts under `.agent-os/runs/<run-id>/`, then `agent-os audit <run-id> .` and `agent-os close <run-id> .`. Full walkthrough below.

---

## When to use Agent OS (v0)

Agent OS v0 is **not** meant for tiny one-shot tasks where a normal prompt is enough. It is meant for **governed delegation** where mission, authority, evidence, audit, and closure matter — work with real scope risk, a need for reviewable artifacts, or handoffs that must not close until required fields are filled.

For concrete dogfood evidence and the usage-threshold tradeoff, see `docs/dogfood-001-todo-cli.md` (first run), `docs/dogfood-002-markdown-evidence-pack.md` (medium-scope local CLI), `docs/dogfood-003-local-site-audit.md` (medium-risk local site audit), and `docs/dogfood-004-json-config-linter.md` (full evidence stack on a JSON config linter). For what counts as acceptable evidence and how to capture it without turning Agent OS into a runtime, see `docs/evidence-capture-doctrine-v0.md`. For what evidence helpers may and may not do, see `docs/evidence-capture-boundaries-v0.md` (`agent-os evidence add`, `agent-os evidence add-file`, `agent-os evidence add-command-output`, and `agent-os evidence snapshot-git` are implemented as registrar-only; `snapshot-git` is the narrow explicit read-only Git exception — not arbitrary command execution).

For an end-to-end local planning lifecycle demo, see [`docs/planning-end-to-end-demo.md`](docs/planning-end-to-end-demo.md).

## Requirements

- Python 3.10+
- Standard library only (no runtime dependencies)

## Install from source

```bash
git clone https://github.com/Camarade-dev/agent-os.git
cd agent-os
pip install -e .
```

Verify the CLI:

```bash
agent-os --help
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Minimal example workflow

In any local project directory:

```bash
# 1. Bootstrap a workspace
agent-os init .

# 1b. Bootstrap a planning workspace (registrar only; no runs or agents)
agent-os planning init <plan-id> .

# 1c. Inspect an existing planning workspace (read-only)
agent-os planning status <plan-id> .

# 1d. Weak read-only validation of a planning workspace (does not approve execution)
agent-os planning validate <plan-id> .

# 1e. Record an owner decision (evidence only; does not execute or create runs)
agent-os planning decide <plan-id> . --decision REQUEST_REVISION --summary "fix scope"

# 1f. List owner decision records (read-only)
agent-os planning decisions list <plan-id> .

# 1g. Apply artifact-progress manifest transitions (no owner decision)
agent-os planning progress <plan-id> . --to CONTEXT_READY

# 1h. Apply an explicit manifest transition authorized by owner decision
agent-os planning transition <plan-id> . --to APPROVED_FOR_RUN_PROPOSALS

# 2. Create a run from templates
agent-os mission .

# 3. Check status and unfilled required fields
agent-os status .

# 4. Fill run artifacts under .agent-os/runs/<run-id>/ (mission, scope,
#    authority, autonomy, evidence, owner decision, closure verdict)
#    Or append evidence with the registrar helper:
#    agent-os evidence add <run-id> . --note "pytest: 6 passed"
#    agent-os evidence add-file <run-id> . --file path/to/report.txt --note "build report"
#    agent-os evidence add-command-output <run-id> . \
#      --command "python -m unittest discover -s tests -v" \
#      --output-file /tmp/test-out.txt --note "unit test output from local shell"
#    agent-os evidence snapshot-git <run-id> . --note "pre-commit repository state"
#    agent-os evidence list <run-id> .   # read-only index of structured entries

# 5. Record an audit verdict
agent-os audit <run-id> . --verdict pass

# 6. Attempt closure (fail-closed until all required fields are filled)
agent-os close <run-id> .
```

Required fields for closure:

- mission statement
- scope
- authority
- autonomy level or autonomy gates
- at least one evidence item
- audit verdict
- owner decision
- closure verdict

## CLI

```bash
agent-os --help
agent-os init [PATH]          # bootstrap .agent-os/ in a target project
agent-os planning init PLAN_ID [PATH]  # bootstrap DRAFT planning workspace (registrar only)
agent-os planning status PLAN_ID [PATH]  # inspect planning workspace structure (read-only)
agent-os planning validate PLAN_ID [PATH]  # weak read-only validation (does not approve execution)
agent-os planning decide PLAN_ID [PATH] --decision DECISION --summary "..."  # record owner decision (evidence only)
agent-os planning decisions list PLAN_ID [PATH]  # list owner decision records (read-only)
agent-os planning progress PLAN_ID [PATH] --to STATUS  # artifact-progress manifest transition (no owner decision)
agent-os planning transition PLAN_ID [PATH] --to STATUS  # explicit manifest transition (owner decision required)
agent-os mission [PATH]       # create a new run from templates
agent-os status [PATH]        # list runs and fields blocking closure
agent-os audit RUN_ID [PATH]  # record an audit verdict
agent-os evidence add RUN_ID [PATH] --note "..."  # append evidence block (registrar only)
agent-os evidence add-file RUN_ID [PATH] --file <path> --note "..."  # register file path (reference only)
agent-os evidence add-command-output RUN_ID [PATH] --command "..." --output-file <path> --note "..."  # register command + output (no execution)
agent-os evidence snapshot-git RUN_ID [PATH] --note "..." [--repo <path>] [--no-include-diff-stat]  # read-only git snapshot (fixed allowlist only)
agent-os evidence list RUN_ID [PATH]  # read-only index of structured evidence entries
agent-os close RUN_ID [PATH]  # attempt fail-closed run closure
```

## Repository layout

```
agent-os/
  agent_os/           # Python package and CLI
    templates/        # run artifact templates (packaged with install)
  docs/               # protocol documentation
  examples/           # manual workflow examples
  tests/              # unittest suite
```

## Philosophy

Agent OS v0 is intentionally minimal: CLI and scripts only, local-only, no cloud, no UI, no API server, no multi-user features, no billing, and no autonomous agent execution. The protocol lives in markdown artifacts under `.agent-os/` inside projects that adopt it.

See [`docs/why-agent-os.md`](docs/why-agent-os.md) for the epistemic rationale, `docs/v0-release-boundary.md` for the v0 release boundary, `docs/thesis.md` for the product thesis, `docs/dogfood-001-todo-cli.md`, `docs/dogfood-002-markdown-evidence-pack.md`, `docs/dogfood-003-local-site-audit.md`, and `docs/dogfood-004-json-config-linter.md` for dogfood synthesis, `docs/evidence-capture-doctrine-v0.md` for evidence capture doctrine, `docs/evidence-capture-boundaries-v0.md` for evidence helper boundaries, [`docs/planning-layer-doctrine.md`](docs/planning-layer-doctrine.md) for the governed planning layer (doctrine extension, not v0 core), [`docs/planning-workspace-layout.md`](docs/planning-workspace-layout.md) for where planning packages live on disk, [`docs/planning-decision-transition-doctrine.md`](docs/planning-decision-transition-doctrine.md) for how owner decisions relate to future manifest transitions, and `examples/manual-agent-workflow.md` for a walkthrough.
