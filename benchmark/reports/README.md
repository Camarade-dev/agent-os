# benchmark/reports/

Local output directory for generated Admissible run artifacts (e.g.
`latest_trace.json` from `admissible.runner.compare_runner --trace-out`,
and `latest_trace.html` from `admissible.harness.viewer`).

These are generated smoke-run artifacts, not committed benchmark results.
This README exists only so the directory itself is tracked in git; the
generated JSON/HTML files in this directory are untracked and should stay
that way unless an owner explicitly decides to keep a specific snapshot.
