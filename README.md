# Agent OS

Agent OS is a **local epistemic protocol** for governed agentic execution. It is not a dashboard, agent panel, SaaS, or orchestration platform.

It helps a human owner delegate work to fallible coding and research agents by structuring:

- mission and scope
- authority and autonomy gates
- context separation
- evidence and audit
- owner decision and closure
- memory hygiene

**Agent OS v0 does not execute agents, orchestrate agents, or replace owner judgment.** It provides a filesystem-based protocol and CLI to create, review, and close governed runs locally.

## When to use Agent OS (v0)

Agent OS v0 is **not** meant for tiny one-shot tasks where a normal prompt is enough. It is meant for **governed delegation** where mission, authority, evidence, audit, and closure matter — work with real scope risk, a need for reviewable artifacts, or handoffs that must not close until required fields are filled.

For concrete dogfood evidence and the usage-threshold tradeoff, see `docs/dogfood-001-todo-cli.md` (first run), `docs/dogfood-002-markdown-evidence-pack.md` (medium-scope local CLI), and `docs/dogfood-003-local-site-audit.md` (medium-risk local site audit). For what counts as acceptable evidence and how to capture it without turning Agent OS into a runtime, see `docs/evidence-capture-doctrine-v0.md`. For what evidence helpers may and may not do, see `docs/evidence-capture-boundaries-v0.md` (`agent-os evidence add` and `agent-os evidence add-file` are implemented as registrar-only).

## Requirements

- Python 3.10+
- Standard library only (no runtime dependencies)

## Install from source

```bash
git clone <repo-url> agent-os
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

# 2. Create a run from templates
agent-os mission .

# 3. Check status and unfilled required fields
agent-os status .

# 4. Fill run artifacts under .agent-os/runs/<run-id>/ (mission, scope,
#    authority, autonomy, evidence, owner decision, closure verdict)
#    Or append evidence with the registrar helper:
#    agent-os evidence add <run-id> . --note "pytest: 6 passed"
#    agent-os evidence add-file <run-id> . --file path/to/report.txt --note "build report"
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
agent-os mission [PATH]       # create a new run from templates
agent-os status [PATH]        # list runs and fields blocking closure
agent-os audit RUN_ID [PATH]  # record an audit verdict
agent-os evidence add RUN_ID [PATH] --note "..."  # append evidence block (registrar only)
agent-os evidence add-file RUN_ID [PATH] --file <path> --note "..."  # register file path (reference only)
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

See `docs/thesis.md` for the product thesis, `docs/dogfood-001-todo-cli.md`, `docs/dogfood-002-markdown-evidence-pack.md`, and `docs/dogfood-003-local-site-audit.md` for dogfood synthesis, `docs/evidence-capture-doctrine-v0.md` for evidence capture doctrine, `docs/evidence-capture-boundaries-v0.md` for evidence helper boundaries, and `examples/manual-agent-workflow.md` for a walkthrough.
