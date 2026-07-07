"""Admissible action-admission decision labels and precedence.

These labels apply to Admissible action admission decisions: whether a
proposed side-effecting AI-agent action should be admitted into execution
at the execution boundary. See docs/Admissible_THESIS.md,
docs/Admissible_ACTION_ENVELOPE.md, and docs/Admissible_BENCHMARK_SPEC.md.

They do not replace, extend, or reuse Agent OS owner-decision labels
(PLANNING_OWNER_DECISION, OWNER_READINESS_DECISION, and the requirements
extraction/validation/approval owner decisions in `agent_os.orchestrator`).
Agent OS owner decisions govern whether an internal planning artifact may
be promoted to the next stage of a coding workflow; Admissible decisions
govern whether a proposed side-effecting action may proceed in the real
world. See docs/admissible-agent-os-lineage.md for the full boundary.

This module does not evaluate action envelopes. It defines only the five
canonical decision labels and the precedence rule for resolving multiple
plausible labels into one. Envelope evaluation belongs to a future
evaluator module.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Union


class AdmissionDecision(str, Enum):
    """One of Admissible's five canonical execution-boundary decisions."""

    ALLOW = "ALLOW"
    ALLOW_WITH_LIMITS = "ALLOW_WITH_LIMITS"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    REFUSE = "REFUSE"


# Highest precedence first. If multiple labels are plausible for one
# proposed action, the highest-precedence label captures the strongest
# blocker to execution (see ACTION_ENVELOPE.md "Decision label precedence").
_PRECEDENCE_ORDER: tuple[AdmissionDecision, ...] = (
    AdmissionDecision.REFUSE,
    AdmissionDecision.REQUIRE_HUMAN_APPROVAL,
    AdmissionDecision.REQUEST_MORE_EVIDENCE,
    AdmissionDecision.ALLOW_WITH_LIMITS,
    AdmissionDecision.ALLOW,
)

_PRECEDENCE_RANK = {label: rank for rank, label in enumerate(_PRECEDENCE_ORDER)}


def is_valid_decision_label(value: object) -> bool:
    """Return True if value is a recognized AdmissionDecision label (str or enum)."""
    if isinstance(value, AdmissionDecision):
        return True
    if isinstance(value, str):
        try:
            AdmissionDecision(value)
        except ValueError:
            return False
        return True
    return False


def _coerce(label: object) -> AdmissionDecision:
    if isinstance(label, AdmissionDecision):
        return label
    if isinstance(label, str):
        try:
            return AdmissionDecision(label)
        except ValueError:
            raise ValueError(f"unknown decision label: {label!r}") from None
    raise ValueError(
        "decision label must be a string or AdmissionDecision, "
        f"got {type(label).__name__}: {label!r}"
    )


def resolve_precedence(
    candidate_labels: Iterable[Union[str, AdmissionDecision]],
) -> AdmissionDecision:
    """Return the highest-precedence label among candidate_labels.

    Precedence (highest to lowest): REFUSE > REQUIRE_HUMAN_APPROVAL >
    REQUEST_MORE_EVIDENCE > ALLOW_WITH_LIMITS > ALLOW. Use this when a
    proposed action satisfies multiple blocking conditions at once; the
    result is the label representing the strongest blocker to execution.

    Accepts strings or AdmissionDecision values, in any mix and any order.
    Duplicate labels do not affect the result. Raises ValueError for empty
    input, an unrecognized string, or a value that is neither a string nor
    an AdmissionDecision. Never silently coerces invalid values.
    """
    candidates = list(candidate_labels)
    if not candidates:
        raise ValueError("resolve_precedence requires at least one candidate label")

    resolved = [_coerce(label) for label in candidates]
    return min(resolved, key=lambda label: _PRECEDENCE_RANK[label])
