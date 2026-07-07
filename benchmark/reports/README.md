# benchmark/reports/

This directory holds two different kinds of files. Do not confuse them.

**Generated, untracked run artifacts** — e.g. `latest_trace.json` from
`admissible.runner.compare_runner --trace-out`, and `latest_trace.html`
from `admissible.harness.viewer`; also `demo_trace.json` and
`demo_trace.html` from `admissible.runner.demo_trace` (mock mode), and
`live_demo_trace.json` / `live_demo_trace.html` from
`admissible.runner.demo_trace --provider env-http` (live mode, opt-in).
All of these are generated smoke-run artifacts, not committed benchmark
results. They are untracked and should stay that way unless an owner
explicitly decides to keep a specific snapshot.

**Curated, committed reports** — e.g. `demo-pack.json` and `demo-pack.md`,
a hand-selected demo scenario pack built from the Tier 1 enriched seed
cases; and `demo-script.json` and `demo-script.md`, a narrated walkthrough
script that turns the demo pack and its generated `demo_trace.html` into a
presentable sequence for a mentor, reviewer, recruiter, or investor
conversation. These are checked into git deliberately because they are
authored, reviewed artifacts, not run output. Like everything else in
`benchmark/reports/`, they are explicitly not benchmark results (see each
file's own claim boundary).
