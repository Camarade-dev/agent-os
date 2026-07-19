"""Presentation-layer enumerations for the Admissible product read model.

This module is deliberately self-contained. It does NOT import the production
``admissible.delegated_gate`` vocabulary, the profile registry, or any other
production module. The known canonical-classification strings below *mirror* the
persisted vocabulary but are independently defined so this presentation lane can
be audited, cherry-picked and integrated without coupling to reconstruction
authority.

Every enum carries an explicit ``UNKNOWN``/``UNSUPPORTED``/``ABSENT`` member so
that missing evidence and unrecognised future values are represented as data
rather than silently coerced into a success-looking default.
"""

from __future__ import annotations

from enum import Enum


class PresenceState(str, Enum):
    """How a single persisted evidence record presents to the reader.

    ``INCONSISTENT`` covers malformed JSON, duplicate keys, oversized files and
    refused reparse points. Absent evidence is never ``INCONSISTENT`` and
    malformed evidence is never silently treated as ``ABSENT``.
    """

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    INCONSISTENT = "INCONSISTENT"


class ClassificationKind(str, Enum):
    """Display kind for a persisted canonical classification string.

    This describes the *canary/execution* terminal recorded by the harness. It
    never implies product admission: a ``SUCCESS`` canary classification with no
    authoritative product verdict still yields an ``UNKNOWN`` product verdict.
    """

    SUCCESS = "SUCCESS"
    NON_SUCCESS = "NON_SUCCESS"
    UNSUPPORTED = "UNSUPPORTED"
    ABSENT = "ABSENT"


class ExecutionState(str, Enum):
    """Observed lifecycle of the native provider process, harness-grounded."""

    UNOBSERVED = "UNOBSERVED"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"


class OutcomeState(str, Enum):
    """Tri-state result for a bounded pipeline stage (material, verifier, ...)."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    ABSENT = "ABSENT"
    INCONSISTENT = "INCONSISTENT"


class FailingBoundary(str, Enum):
    """The earliest stage at which a run was refused, when determinable."""

    NONE = "NONE"
    PROCESS = "PROCESS"
    MATERIAL_ELIGIBILITY = "MATERIAL_ELIGIBILITY"
    BEHAVIORAL_VERIFIER = "BEHAVIORAL_VERIFIER"
    CHECKPOINT = "CHECKPOINT"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class ProductVerdict(str, Enum):
    """Authoritative product admission verdict.

    ``UNKNOWN`` is the default and MUST NOT be inferred from a provider exit
    code, a clean Git state or a final-status filename. It only becomes an
    ``ADMITTED_*``/``REFUSED`` value when supplied by an authoritative truth
    provider or an explicit persisted product block. Future/unrecognised verdict
    strings become ``UNSUPPORTED`` with the raw value preserved.
    """

    ADMITTED_OBSERVED = "ADMITTED_OBSERVED"
    ADMITTED_VERIFIED = "ADMITTED_VERIFIED"
    REFUSED = "REFUSED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class VerificationMode(str, Enum):
    """Authoritative verification tier, when supplied."""

    OBSERVED_ONLY = "OBSERVED_ONLY"
    FROZEN_BEHAVIORAL = "FROZEN_BEHAVIORAL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class VerdictSource(str, Enum):
    """Provenance of the *effective* product verdict.

    Only an authoritative reconstruction may source an effective product verdict.
    A persisted product block is NEVER an effective source: it is demoted to an
    unverified claim (see :class:`TruthStatus` and the ``claimed_*`` fields on
    ``ProductVerdictView``). A contradiction between an authoritative verdict and
    a persisted claim is expressed via ``consistent=False``, not a distinct
    source, so the authoritative verdict is never erased by the conflict.
    """

    NONE = "NONE"
    AUTHORITATIVE_RECONSTRUCTION = "AUTHORITATIVE_RECONSTRUCTION"


class TruthStatus(str, Enum):
    """Availability of the authoritative reconstruction seam for a run.

    This is the single signal that gates admission. ``AUTHORITATIVE`` is the only
    value under which an ``ADMITTED_*``/``REFUSED`` product verdict may be
    established. Provider absence (``NOT_CONFIGURED``) is deliberately distinct
    from provider failure (``UNAVAILABLE``/``ERROR``); a provider that runs but
    supplies no verdict is ``NO_VERDICT`` (still non-admitting).
    """

    NOT_CONFIGURED = "NOT_CONFIGURED"
    AUTHORITATIVE = "AUTHORITATIVE"
    NO_VERDICT = "NO_VERDICT"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class HumanDisposition(str, Enum):
    """Human review / acceptance state, distinct from every machine verdict."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NONE = "NONE"
    UNSUPPORTED = "UNSUPPORTED"


class CompletenessState(str, Enum):
    """Aggregate evidence completeness for a run."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    INCONSISTENT = "INCONSISTENT"


class PresentationStatus(str, Enum):
    """Top-level display status.

    This is a *presentation* concept derived only from (a) an authoritative
    product verdict when supplied and (b) the persisted canonical classification
    and evidence completeness otherwise. It never asserts product admission from
    persisted canary facts alone.
    """

    ADMITTED = "ADMITTED"
    REFUSED = "REFUSED"
    INCOMPLETE = "INCOMPLETE"
    INCONSISTENT = "INCONSISTENT"
    UNKNOWN = "UNKNOWN"


# --- Canonical classification vocabulary (independently mirrored) -------------

# Canary/execution terminals the harness records where the canary reached or
# passed the checkpoint boundary. These describe the canary self-test only.
_SUCCESS_CLASSIFICATIONS = frozenset(
    {
        "CHECKPOINT_CAPTURED",
        "CHECKPOINT_CAPTURED_CANARY_SUCCESS",
    }
)

# Canary/execution terminals the harness records for a refused or non-admitted
# run. Anything not in either set is treated as an unsupported future value.
_NON_SUCCESS_CLASSIFICATIONS = frozenset(
    {
        "PREFLIGHT_BLOCKED",
        "EXECUTION_RESULT_MISSING_NO_RETRY",
        "ATTEMPT_RESERVED_LAUNCH_OUTCOME_UNKNOWN",
        "PROCESS_OBSERVATION_MISSING",
        "EXECUTION_ELIGIBILITY_MISSING",
        "ACCEPTED_RESULT_MISSING",
        "PROCESS_SPAWN_FAILED",
        "PROCESS_OBSERVATION_PUBLICATION_FAILED",
        "PROCESS_FAILED",
        "TIMED_OUT",
        "CLEANUP_UNCERTAIN",
        "WORKSPACE_BOUNDARY_BLOCKED",
        "PRECAPTURE_ELIGIBILITY_FAILED",
        "CAPTURE_ATTEMPT_AMBIGUOUS",
        "CHECKPOINT_CAPTURE_FAILED",
        "DURABILITY_UNCERTAIN",
    }
)


def classify_classification(raw: object) -> ClassificationKind:
    """Map a persisted canonical classification string to a display kind.

    Unknown/future strings become ``UNSUPPORTED`` (never guessed as success);
    ``None`` becomes ``ABSENT``.
    """

    if raw is None:
        return ClassificationKind.ABSENT
    if not isinstance(raw, str):
        return ClassificationKind.UNSUPPORTED
    if raw in _SUCCESS_CLASSIFICATIONS:
        return ClassificationKind.SUCCESS
    if raw in _NON_SUCCESS_CLASSIFICATIONS:
        return ClassificationKind.NON_SUCCESS
    return ClassificationKind.UNSUPPORTED


def coerce_product_verdict(raw: object) -> tuple[ProductVerdict, str | None]:
    """Return ``(verdict, raw_value_if_unsupported)`` for a product-verdict value.

    A recognised string maps to its member with no raw echo. An unrecognised
    non-empty string maps to ``UNSUPPORTED`` with the raw value preserved so the
    presentation never invents an admission verdict for a future value.
    """

    if raw is None:
        return ProductVerdict.UNKNOWN, None
    if isinstance(raw, str):
        for member in (
            ProductVerdict.ADMITTED_OBSERVED,
            ProductVerdict.ADMITTED_VERIFIED,
            ProductVerdict.REFUSED,
        ):
            if raw == member.value:
                return member, None
        if raw == ProductVerdict.UNKNOWN.value:
            return ProductVerdict.UNKNOWN, None
        return ProductVerdict.UNSUPPORTED, raw
    return ProductVerdict.UNSUPPORTED, repr(raw)


def coerce_verification_mode(raw: object) -> tuple[VerificationMode, str | None]:
    """Return ``(mode, raw_value_if_unsupported)`` for a verification-mode value."""

    if raw is None:
        return VerificationMode.UNKNOWN, None
    if isinstance(raw, str):
        for member in (
            VerificationMode.OBSERVED_ONLY,
            VerificationMode.FROZEN_BEHAVIORAL,
        ):
            if raw == member.value:
                return member, None
        if raw == VerificationMode.UNKNOWN.value:
            return VerificationMode.UNKNOWN, None
        return VerificationMode.UNSUPPORTED, raw
    return VerificationMode.UNSUPPORTED, repr(raw)


def coerce_human_disposition(raw: object) -> tuple[HumanDisposition, str | None]:
    """Return ``(disposition, raw_value_if_unsupported)`` for a human decision."""

    if raw is None:
        return HumanDisposition.NONE, None
    if isinstance(raw, str):
        normalised = raw.strip().upper()
        for member in (HumanDisposition.ACCEPTED, HumanDisposition.REJECTED):
            if normalised == member.value:
                return member, None
        if normalised in ("", "NONE", "PENDING"):
            return HumanDisposition.NONE, None
        return HumanDisposition.UNSUPPORTED, raw
    return HumanDisposition.UNSUPPORTED, repr(raw)
