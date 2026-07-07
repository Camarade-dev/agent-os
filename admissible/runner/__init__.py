"""Admissible baseline runners.

Runner modules produce a decision_output-shaped dict from a system
under test, given a bare action envelope. See
admissible.runner.baseline_runner for the frontier-direct baseline
(the "frontier model alone" condition, compared against
admissible.evaluator.rules_only via benchmark/scoring/score_decisions.py).

Import functions from admissible.runner.baseline_runner directly (not
re-exported here) so that `python -m admissible.runner.baseline_runner`
does not trigger a duplicate-module-import warning.
"""
