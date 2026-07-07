# Agent OS

**v0.1.0** — local governed-delegation prototype · [release notes](docs/release-notes-v0.1.0.md) · [why Agent OS](docs/why-agent-os.md)

**Live static demo:** https://camarade-dev.github.io/agent-os-demo-governed-agent-chat/ — see how Agent OS wraps a familiar coding-agent chat with mission, scope, evidence, audit, owner decision, and closure.

Agent OS is a **local filesystem protocol and CLI** for governed delegation to fallible coding and research agents. It is not a dashboard, SaaS, runtime, orchestrator, benchmark, or agent panel.

## Admissible

This repository also hosts **Admissible** — a benchmark/spec/prototype direction for evaluating whether proposed side-effecting AI-agent actions should be admitted at the execution boundary. It is separate from the Agent OS v0 CLI surface below.

**Core distinction:** The model may propose what could be done. Admissible evaluates what may be done.

Canonical objects in the current harness:

- **action envelope** — one proposed side-effecting action at the execution boundary;
- **admission decision** — ALLOW, ALLOW_WITH_LIMITS, REQUEST_MORE_EVIDENCE, REQUIRE_HUMAN_APPROVAL, or REFUSE;
- **gold annotation** — benchmark ground truth, stored separately from the envelope;
- **scoring result** — comparison of a system's decision against gold;
- **run trace** — structured record of a benchmark run;
- **visual trace viewer** — static HTML report over a run trace;
- **demo scenario pack** — curated subset of seed cases for walkthroughs.

### Current status

The repo currently contains:

- canonical Admissible docs;
- JSON schemas;
- 25 Tier 1 enriched seed cases;
- gold annotations;
- rules-only reference evaluator;
- frontier-direct mock baseline runner;
- scoring harness;
- comparison runner;
- run trace schema/generator;
- static trace viewer;
- curated 8-case demo pack;
- demo script narrative.

This is a smoke-tested internal harness, not a public benchmark result.

### Admissible quickstart

**Focused tests:**

```bash
python -m unittest tests.test_admissible_decision tests.test_admissible_rules_only tests.test_admissible_scoring tests.test_admissible_baseline_runner tests.test_admissible_compare_runner tests.test_admissible_trace tests.test_admissible_visual_trace_viewer tests.test_admissible_demo_pack tests.test_admissible_demo_trace tests.test_admissible_demo_script -v
```

**Generate demo trace and HTML:**

```bash
python -m admissible.runner.demo_trace \
  --demo-pack benchmark/reports/demo-pack.json \
  --gold benchmark/annotations/gold_labels.jsonl \
  --mock-response benchmark/examples/mock_frontier_response.json \
  --trace-out benchmark/reports/demo_trace.json \
  --html-out benchmark/reports/demo_trace.html
```

Open `benchmark/reports/demo_trace.html` in a browser.

Optional live demo trace (requires `ADMISSIBLE_MODEL_*` env vars; writes separate `live_demo_trace.*` artifacts):

```bash
python -m admissible.runner.demo_trace \
  --demo-pack benchmark/reports/demo-pack.json \
  --gold benchmark/annotations/gold_labels.jsonl \
  --provider env-http \
  --trace-out benchmark/reports/live_demo_trace.json \
  --html-out benchmark/reports/live_demo_trace.html
```

### Optional live model provider

The default demo path uses `frontier_direct_mock`.

A live frontier-direct baseline can be run by configuring:

- `ADMISSIBLE_MODEL_API_URL`
- `ADMISSIBLE_MODEL_API_KEY`
- `ADMISSIBLE_MODEL_NAME`
- optionally `ADMISSIBLE_MODEL_TIMEOUT_SECONDS`

Live model execution is optional and is not required for tests.

Live runs remain Tier 1 enriched smoke tests, not benchmark results.

### Documentation

- [`docs/Admissible_THESIS.md`](docs/Admissible_THESIS.md) — thesis and design rationale
- [`docs/Admissible_ACTION_ENVELOPE.md`](docs/Admissible_ACTION_ENVELOPE.md) — action envelope specification
- [`docs/Admissible_BENCHMARK_SPEC.md`](docs/Admissible_BENCHMARK_SPEC.md) — benchmark design: cases, gold, baselines, scoring
- [`docs/admissible-agent-os-lineage.md`](docs/admissible-agent-os-lineage.md) — how Admissible relates to Agent OS
- [`benchmark/reports/demo-pack.md`](benchmark/reports/demo-pack.md) — curated demo scenario pack
- [`benchmark/reports/demo-script.md`](benchmark/reports/demo-script.md) — narrated demo walkthrough

### Agent OS boundary

**Agent OS** is the prior/internal governed-delegation substrate (mission, scope, evidence, audit, owner decision, closure). **Admissible** is the current benchmark/prototype direction for execution-boundary action admission.

Existing Agent OS CLI/orchestrator concepts are not automatically Admissible benchmark semantics. Agent OS "admissible for promotion" (a planning artifact ready for owner review) is not Admissible action admissibility (whether a side-effecting action may execute).

### Non-claims

- This is not a benchmark result.
- The current frontier baseline in the demo path is a mock plumbing baseline, not a live frontier model.
- The rules-only evaluator is designed for Tier 1 enriched cases.
- The current seed set is small, hand-authored, and single-author annotated.
- The project does not yet show generalization to raw or adversarial cases.
- The project is not production-ready infrastructure.

### Next technical step

A live model provider boundary is available behind `ModelClient` (`admissible.runner.model_clients`). The default demo and test paths remain mock-only; optional live runs use `--provider env-http` or the `frontier_direct_live` compare-runner system when environment variables are set.

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

For an end-to-end local planning lifecycle demo, see [`docs/planning-end-to-end-demo.md`](docs/planning-end-to-end-demo.md). For the `PLANNING_RUN_SLICE` JSON contract (future runner import; optional in workspaces today), see [`docs/planning-structured-slice-format.md`](docs/planning-structured-slice-format.md).

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

See [`docs/why-agent-os.md`](docs/why-agent-os.md) for the epistemic rationale, `docs/v0-release-boundary.md` for the v0 release boundary, `docs/thesis.md` for the product thesis, `docs/dogfood-001-todo-cli.md`, `docs/dogfood-002-markdown-evidence-pack.md`, `docs/dogfood-003-local-site-audit.md`, and `docs/dogfood-004-json-config-linter.md` for dogfood synthesis, `docs/evidence-capture-doctrine-v0.md` for evidence capture doctrine, `docs/evidence-capture-boundaries-v0.md` for evidence helper boundaries, [`docs/planning-layer-doctrine.md`](docs/planning-layer-doctrine.md) for the governed planning layer (doctrine extension, not v0 core), [`docs/planning-workspace-layout.md`](docs/planning-workspace-layout.md) for where planning packages live on disk, [`docs/planning-structured-slice-format.md`](docs/planning-structured-slice-format.md) for structured plan slice JSON (future runner import), [`docs/planning-decision-transition-doctrine.md`](docs/planning-decision-transition-doctrine.md) for how owner decisions relate to future manifest transitions, and `examples/manual-agent-workflow.md` for a walkthrough.
