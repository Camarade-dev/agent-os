"""Admissible scoring harness.

Compares decision outputs against gold annotations and computes the
core Admissible metrics. Deterministic, stdlib-only, never calls a
model. See benchmark/scoring/metrics.md for metric definitions and the
claim boundary that applies to any numbers this package produces.

Import functions from benchmark.scoring.score_decisions directly (not
re-exported here) so that `python -m benchmark.scoring.score_decisions`
does not trigger a duplicate-module-import warning.
"""
