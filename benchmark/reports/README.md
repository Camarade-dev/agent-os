# benchmark/reports/

This directory holds two different kinds of files. Do not confuse them.

**Generated, untracked run artifacts** — e.g. `latest_trace.json` from
`admissible.runner.compare_runner --trace-out`, and `latest_trace.html`
from `admissible.harness.viewer`. These are generated smoke-run artifacts,
not committed benchmark results. They are untracked and should stay that
way unless an owner explicitly decides to keep a specific snapshot.

**Curated, committed reports** — e.g. `demo-pack.json` and `demo-pack.md`,
a hand-selected demo scenario pack built from the Tier 1 enriched seed
cases. These are checked into git deliberately because they are authored,
reviewed artifacts, not run output. Like everything else in `benchmark/reports/`,
they are explicitly not benchmark results (see each file's own claim
boundary).
