"""The single adapter/extractor boundary for authoritative product verdicts.

Future G1 integration changes *this module only*. Presentation types depend on
``ProductVerdictView``; they never parse a truth-provider payload themselves.

The extractor is tolerant of JSON nesting: a verdict may appear at the top level
or inside a ``product`` / ``admission`` container. It never assumes an exact
shape. Conflicting authoritative and persisted values yield an inconsistent
result. Unknown/future verdict strings are preserved raw as ``UNSUPPORTED``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .enums import (
    ProductVerdict,
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


def extract_product_verdict(
    authoritative: Mapping[str, object] | None,
    persisted_product: Mapping[str, object] | None,
) -> ProductVerdictView:
    """Reconcile an authoritative reconstruction and a persisted product block.

    * Neither supplies a verdict -> ``UNKNOWN`` (source ``NONE``). This is the
      correct result for legacy runs and is never inferred from exit codes.
    * Exactly one source -> that source, tagged accordingly.
    * Both sources disagree -> ``consistent=False`` with source ``CONFLICT``.
    * Both agree -> authoritative reconstruction is the reported source.
    """

    auth = _from_source(authoritative)
    pers = _from_source(persisted_product)

    if auth is None and pers is None:
        return ProductVerdictView(
            verdict=ProductVerdict.UNKNOWN,
            raw_verdict=None,
            verification_mode=VerificationMode.UNKNOWN,
            raw_verification_mode=None,
            behavioral_non_claim=None,
            source=VerdictSource.NONE,
            consistent=True,
            notes=("no authoritative product verdict supplied; verdict remains UNKNOWN",),
        )

    if auth is not None and pers is None:
        return _view(auth, VerdictSource.AUTHORITATIVE_RECONSTRUCTION, True, ())

    if auth is None and pers is not None:
        return _view(pers, VerdictSource.PERSISTED_PRODUCT_BLOCK, True, ())

    # Both sources supplied a verdict; reconcile.
    assert auth is not None and pers is not None
    agree = (
        auth.verdict is pers.verdict
        and auth.raw_verdict == pers.raw_verdict
        and auth.mode is pers.mode
        and auth.raw_mode == pers.raw_mode
    )
    if agree:
        return _view(auth, VerdictSource.AUTHORITATIVE_RECONSTRUCTION, True, ("authoritative and persisted product blocks agree",))
    note = (
        "conflict: authoritative verdict "
        f"{_render(auth.verdict, auth.raw_verdict)} vs persisted verdict "
        f"{_render(pers.verdict, pers.raw_verdict)}"
    )
    return _view(auth, VerdictSource.CONFLICT, False, (note,))


def _view(
    source_verdict: _SourceVerdict,
    source: VerdictSource,
    consistent: bool,
    extra_notes: tuple[str, ...],
) -> ProductVerdictView:
    return ProductVerdictView(
        verdict=source_verdict.verdict,
        raw_verdict=source_verdict.raw_verdict,
        verification_mode=source_verdict.mode,
        raw_verification_mode=source_verdict.raw_mode,
        behavioral_non_claim=source_verdict.non_claim,
        source=source,
        consistent=consistent,
        notes=extra_notes,
    )


def _render(verdict: ProductVerdict, raw: str | None) -> str:
    if verdict is ProductVerdict.UNSUPPORTED and raw is not None:
        return f"UNSUPPORTED({raw!r})"
    return verdict.value
