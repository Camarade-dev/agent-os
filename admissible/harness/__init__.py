"""Admissible visual trace viewer harness (Slice J).

Read-only local tooling for inspecting Admissible run traces
(benchmark/schemas/run_trace.schema.json) as static HTML. See
admissible.harness.viewer for load_trace / render_trace_html /
write_trace_html and the `python -m admissible.harness.viewer` CLI.

This is a post-run inspection tool only: it does not call a model,
does not build prompts, does not pass gold annotations anywhere but
onto the page, does not mutate trace JSON, does not score anything
beyond what the trace already records, and does not import from
agent_os.

Import functions from admissible.harness.viewer directly (not
re-exported here) so that `python -m admissible.harness.viewer` does
not trigger a duplicate-module-import warning.
"""
