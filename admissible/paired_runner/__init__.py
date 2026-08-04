"""Pure Milestone 1 executable architecture specification.

This namespace contains immutable data models, canonicalization, identity
binding, and parity checking only.  It deliberately has no model transport,
filesystem tool, subprocess executor, policy implementation, owner broker,
or provider integration.
"""

from .canonical import (
    CanonicalizationError,
    Fingerprint,
    NonCanonicalEncodingError,
    canonical_bytes,
    fingerprint,
    fingerprint_bytes,
    parse_canonical_json,
    strict_json_loads,
)
from .comparison import ParityRefused, ParityReport, check_parity, require_parity
from .identities import IdentityReference, RunIdentity, SessionIdentity
from .specification import (
    AllowedConditionDifferences,
    BudgetLimits,
    BudgetState,
    BudgetUsage,
    CanonicalProposal,
    CausalPredecessor,
    ClockObservation,
    ComparativeManifest,
    ConditionConfiguration,
    EffectReceipt,
    EffectReservation,
    EvaluatorSpecification,
    ExperimentSpecification,
    HumanInterventionRecord,
    ModeDecision,
    TerminalManifest,
    canonical_object_bytes,
    validate_unique_proposal_ids,
)

__all__ = [
    "AllowedConditionDifferences",
    "BudgetLimits",
    "BudgetState",
    "BudgetUsage",
    "CanonicalProposal",
    "CanonicalizationError",
    "CausalPredecessor",
    "ClockObservation",
    "ComparativeManifest",
    "ConditionConfiguration",
    "EffectReceipt",
    "EffectReservation",
    "EvaluatorSpecification",
    "ExperimentSpecification",
    "Fingerprint",
    "HumanInterventionRecord",
    "IdentityReference",
    "ModeDecision",
    "NonCanonicalEncodingError",
    "ParityRefused",
    "ParityReport",
    "RunIdentity",
    "SessionIdentity",
    "TerminalManifest",
    "canonical_bytes",
    "canonical_object_bytes",
    "check_parity",
    "fingerprint",
    "fingerprint_bytes",
    "parse_canonical_json",
    "require_parity",
    "strict_json_loads",
    "validate_unique_proposal_ids",
]
