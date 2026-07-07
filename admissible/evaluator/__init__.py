"""Admissible reference evaluators.

Evaluator modules consume an action envelope dict and return a decision
output dict conforming to benchmark/schemas/decision_output.schema.json.
See admissible.evaluator.rules_only for the Tier 1 enriched rules-only
reference evaluator.
"""

from __future__ import annotations

from admissible.evaluator.rules_only import evaluate_envelope

__all__ = ["evaluate_envelope"]
