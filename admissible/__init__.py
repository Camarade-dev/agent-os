"""Admissible: execution-boundary action admission for AI agents.

Separate from the `agent_os` package. See docs/Admissible_THESIS.md,
docs/Admissible_ACTION_ENVELOPE.md, docs/Admissible_BENCHMARK_SPEC.md,
and docs/admissible-agent-os-lineage.md.
"""

from admissible.decision import (
    AdmissionDecision,
    is_valid_decision_label,
    resolve_precedence,
)

__all__ = [
    "AdmissionDecision",
    "is_valid_decision_label",
    "resolve_precedence",
]
