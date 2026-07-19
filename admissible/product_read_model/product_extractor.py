"""The single authority-combination boundary for product verdicts.

This module is the *only* place that decides an effective product verdict from
(1) an authoritative truth-provider reconstruction and (2) a persisted product
claim. Future G1 integration changes *this module only*; presentation types
never parse a truth-provider payload themselves.

Authority rule (non-negotiable):

    Only an authoritative reconstruction may establish an admitted or refused
    effective verdict. A raw persisted ``evidence/product-verdict.json`` block is
    evidence to display, not authority to trust: it is surfaced as an *unverified
    claim* and can never, by itself or under a provider failure, drive the
    effective verdict away from ``UNKNOWN``.

The extractor is tolerant of JSON nesting: a verdict may appear at the top level
or inside a ``product`` / ``admission`` container. Unknown/future verdict strings
are preserved raw as ``UNSUPPORTED`` and never guessed into an admission.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from .enums import (
    ProductVerdict,
    TruthStatus,
    VerdictSource,
    VerificationMode,
    coerce_product_verdict,
    coerce_verification_mode,
)
from .presentation_types import ProductVerdictView

# The canonical behavioral non-claim string reported by G1 for observed-only runs.
CANONICAL_BEHAVIORAL_NON_CLAIM = "Behavior was not independently verified."

_VERDICT_KEYS = ("product_verdict", "verdict", "admission_verdict", "product_admission")
_MODE_KEYS = ("verification_mode", "verification_tier", "mode")
_NON_CLAIM_KEYS = ("behavioral_non_claim", "behavior_non_claim", "non_claim")
_CONTAINER_KEYS = ("product", "product_block", "product_verdict_block", "admission")

_MISSING = object()

_CONCRETE_VERDICTS = (
    ProductVerdict.ADMITTED_OBSERVED,
    ProductVerdict.ADMITTED_VERIFIED,
    ProductVerdict.REFUSED,
)
_ADMISSION_VERDICTS = (
    ProductVerdict.ADMITTED_OBSERVED,
    ProductVerdict.ADMITTED_VERIFIED,
)


class TruthProviderOutcome(str, Enum):
    """How the read model classified what the truth-provider seam produced.

    This is the extractor's *input* signal (the read model owns the I/O and the
    exception handling). It is deliberately distinct from
    :class:`~admissible.product_read_model.enums.TruthStatus`, the resolved status
    the view exposes, because provider absence, provider failure and a provider
    that returned a verdict-free mapping must remain separable.
    """

    NOT_CONFIGURED = "NOT_CONFIGURED"
    RETURNED_MAPPING = "RETURNED_MAPPING"
    RETURNED_INVALID = "RETURNED_INVALID"
    RAISED = "RAISED"


def _tolerant_get(mapping: object, keys: tuple[str, ...]) -> object:
    """Look up the first present key at the top level or in a known container."""

    if not isinstance(mapping, Mapping):
        return _MISSING
    for key in keys:
        if key in mapping:
            return mapping[key]
    for container_key in _CONTAINER_KEYS:
        inner = mapping.get(container_key)
        if isinstance(inner, Mapping):
            for key in keys:
                if key in inner:
                    return inner[key]
    return _MISSING


@dataclass(frozen=True)
class _SourceVerdict:
    verdict: ProductVerdict
    raw_verdict: str | None
    mode: VerificationMode
    raw_mode: str | None
    non_claim: str | None


def _from_source(mapping: object) -> _SourceVerdict | None:
    """Extract a verdict from one source, or ``None`` if it supplies nothing."""

    verdict_raw = _tolerant_get(mapping, _VERDICT_KEYS)
    mode_raw = _tolerant_get(mapping, _MODE_KEYS)
    non_claim_raw = _tolerant_get(mapping, _NON_CLAIM_KEYS)
    if verdict_raw is _MISSING and mode_raw is _MISSING and non_claim_raw is _MISSING:
        return None
    verdict, unsupported_verdict = coerce_product_verdict(
        None if verdict_raw is _MISSING else verdict_raw
    )
    mode, unsupported_mode = coerce_verification_mode(
        None if mode_raw is _MISSING else mode_raw
    )
    non_claim: str | None
    if non_claim_raw is _MISSING:
        non_claim = CANONICAL_BEHAVIORAL_NON_CLAIM if mode is VerificationMode.OBSERVED_ONLY else None
    elif isinstance(non_claim_raw, str):
        non_claim = non_claim_raw
    else:
        non_claim = None
    return _SourceVerdict(verdict, unsupported_verdict, mode, unsupported_mode, non_claim)


def _resolve_outcome(
    outcome: TruthProviderOutcome | None, authoritative: object
) -> TruthProviderOutcome:
    """Infer the outcome for direct callers that pass only a mapping / ``None``.

    ``None`` authoritative input means the seam supplied nothing (not configured);
    a mapping means the provider returned it. Callers that need to express a
    provider *failure* must pass an explicit ``outcome``.
    """

    if outcome is not None:
        return outcome
    if isinstance(authoritative, Mapping):
        return TruthProviderOutcome.RETURNED_MAPPING
    return TruthProviderOutcome.NOT_CONFIGURED


def extract_product_verdict(
    authoritative: Mapping[str, object] | None,
    persisted_product: Mapping[str, object] | None,
    *,
    outcome: TruthProviderOutcome | None = None,
) -> ProductVerdictView:
    """Combine an authoritative reconstruction and a persisted claim, safely.

    ``outcome`` classifies the truth-provider seam result (the read model sets it
    from its own I/O and exception handling). When omitted it is inferred from
    ``authoritative`` for the convenience of unit callers, but a persisted claim
    is *never* promoted to authority on any path.
    """

    outcome = _resolve_outcome(outcome, authoritative)

    # The persisted claim is parsed but is never authoritative.
    claim = _from_source(persisted_product)

    # The authoritative mapping is parsed ONLY when the provider actually returned
    # one. A raised/invalid provider yields no authoritative verdict.
    auth: _SourceVerdict | None = None
    if outcome is TruthProviderOutcome.RETURNED_MAPPING:
        auth = _from_source(authoritative)

    if outcome is TruthProviderOutcome.RAISED:
        truth_status = TruthStatus.ERROR
    elif outcome is TruthProviderOutcome.RETURNED_INVALID:
        truth_status = TruthStatus.UNAVAILABLE
    elif outcome is TruthProviderOutcome.RETURNED_MAPPING:
        truth_status = TruthStatus.AUTHORITATIVE if auth is not None else TruthStatus.NO_VERDICT
    else:  # NOT_CONFIGURED
        truth_status = TruthStatus.NOT_CONFIGURED

    effective_authoritative = truth_status is TruthStatus.AUTHORITATIVE

    # --- effective (authoritative) verdict fields ----------------------------
    if effective_authoritative and auth is not None:
        verdict = auth.verdict
        raw_verdict = auth.raw_verdict
        verification_mode = auth.mode
        raw_verification_mode = auth.raw_mode
        behavioral_non_claim = auth.non_claim
        source = VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    else:
        verdict = ProductVerdict.UNKNOWN
        raw_verdict = None
        verification_mode = VerificationMode.UNKNOWN
        raw_verification_mode = None
        behavioral_non_claim = None
        source = VerdictSource.NONE

    # --- persisted claim fields (unverified, display-only) -------------------
    claim_present = claim is not None
    if claim is not None:
        claimed_verdict = claim.verdict
        raw_claimed_verdict = claim.raw_verdict
        claimed_verification_mode = claim.mode
        raw_claimed_verification_mode = claim.raw_mode
    else:
        claimed_verdict = ProductVerdict.UNKNOWN
        raw_claimed_verdict = None
        claimed_verification_mode = VerificationMode.UNKNOWN
        raw_claimed_verification_mode = None

    # --- consistency + notes -------------------------------------------------
    consistent = True
    notes: list[str] = []

    if effective_authoritative and claim is not None:
        agree = (
            auth is not None
            and auth.verdict is claim.verdict
            and auth.raw_verdict == claim.raw_verdict
            and auth.mode is claim.mode
            and auth.raw_mode == claim.raw_mode
        )
        if agree:
            notes.append("authoritative verdict and persisted claim agree")
        else:
            consistent = False
            notes.append(
                "conflict: authoritative verdict "
                f"{_render(verdict, raw_verdict)} vs unverified persisted claim "
                f"{_render(claimed_verdict, raw_claimed_verdict)}; authoritative value retained"
            )
    elif truth_status in (TruthStatus.ERROR, TruthStatus.UNAVAILABLE):
        detail = (
            "authority reconstruction unavailable (provider error)"
            if truth_status is TruthStatus.ERROR
            else "authority reconstruction unavailable (provider returned no authority)"
        )
        notes.append(detail)
        if claim_present and claimed_verdict in _CONCRETE_VERDICTS:
            # A persisted product claim survives a provider failure: it cannot be
            # verified, so it must never read as admitted. Flag inconsistency.
            consistent = False
            notes.append(
                "unverified persisted claim "
                f"{_render(claimed_verdict, raw_claimed_verdict)} cannot be confirmed while "
                "authority reconstruction is unavailable"
            )
    elif claim_present:
        # No authoritative verdict, but a persisted claim exists. It is displayed
        # as an unverified claim and never becomes the effective verdict.
        note = "persisted product block present but unverified; effective verdict remains UNKNOWN"
        if claimed_verdict in _ADMISSION_VERDICTS:
            note = (
                "persisted product block claims "
                f"{_render(claimed_verdict, raw_claimed_verdict)} but is UNVERIFIED; "
                "effective verdict remains UNKNOWN"
            )
        notes.append(note)
    elif truth_status is TruthStatus.NO_VERDICT:
        notes.append("authoritative provider supplied no product verdict; verdict remains UNKNOWN")
    elif truth_status is TruthStatus.NOT_CONFIGURED:
        notes.append("no authoritative product verdict supplied; verdict remains UNKNOWN")

    return ProductVerdictView(
        verdict=verdict,
        raw_verdict=raw_verdict,
        verification_mode=verification_mode,
        raw_verification_mode=raw_verification_mode,
        behavioral_non_claim=behavioral_non_claim,
        source=source,
        truth_status=truth_status,
        consistent=consistent,
        claim_present=claim_present,
        claimed_verdict=claimed_verdict,
        raw_claimed_verdict=raw_claimed_verdict,
        claimed_verification_mode=claimed_verification_mode,
        raw_claimed_verification_mode=raw_claimed_verification_mode,
        claim_is_authoritative=False,
        notes=tuple(notes),
    )


def _render(verdict: ProductVerdict, raw: str | None) -> str:
    if verdict is ProductVerdict.UNSUPPORTED and raw is not None:
        return f"UNSUPPORTED({raw!r})"
    return verdict.value
