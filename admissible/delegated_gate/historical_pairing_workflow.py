"""Headless confirmation-gated coordinator for historical evaluation pairing.

This module composes the accepted Step 5A pairing authority, the accepted
Step 5B derivation, the accepted Step 5C1 write-once archive, and the accepted
Step 5C2A shared-secret confirmation primitive into one bounded, in-memory,
two-call workflow.  It introduces no HTTP route, no browser surface, no new
canonical document, and no new archive file.

Preparation is pure and writes nothing.  It validates one already-loaded exact
historical V4 authorization payload, derives the exact non-launchable V5
evaluation contract, creates the exact pairing authority, revalidates the
external relation, and pins those exact objects together with the public
Step 5C2A confirmation-message bytes under an opaque ephemeral preparation
identifier.  The configured secret is neither needed nor accessed during
preparation.

Confirmation accepts an independently supplied tag -- never a secret -- and
persists only after that tag verifies against the configured secret through the
accepted Step 5C2A verifier.  The archive is then reloaded through the accepted
public Step 5C1 load API and the reloaded canonical bytes are required to equal
the pinned objects exactly before the preparation is marked consumed.

Review is a third, strictly read-only call.  It resolves one live preparation by
its exact identifier and complete authority fingerprint, snapshots the pinned
objects under the registry lock, and then builds the complete owner review
outside that lock.  Review reserves nothing, confirms nothing, reads no secret,
extends no TTL, persists nothing, and touches no filesystem.  It leaves
preparation and confirmation semantics completely unchanged.

Deliberate, load-bearing limitations
------------------------------------

* Calls routed through this coordinator are confirmation-gated.  Direct calls to
  the lower-level Step 5C1 store remain possible for trusted internal code, and
  this module neither hides, renames, weakens, nor adds a credential parameter
  to that accepted store.
* The three-document archive contains no durable confirmation evidence: no
  receipt, no record, no timestamp, no tag, no tag prefix, no tag hash, no
  expected tag, no secret verifier, and no secret-derived filename.
* An archive alone therefore never proves that a tag was presented, and no read
  model may infer confirmation from archive existence alone.
* This coordinator does not universally enforce confirmation across a Python
  process; it gates only what passes through it.
* ``actor_id`` remains an asserted identifier.  Nothing here authenticates an
  actor, proves fresh secret possession, produces a digital signature, admits a
  result, or says anything about execution, evidence, eligibility, obligation
  satisfaction, claim support, or ``ProductVerdict``.
* The configured secret necessarily stays reachable in coordinator memory for
  the coordinator lifetime.  Python ``bytes`` are immutable, so no memory
  zeroization is performed and none is claimed.

The coordinator accepts an already-loaded payload object.  It never opens a run
root, an evidence root, a preflight document, a source repository, a workspace,
an execution request or result, a checkpoint, a terminal record, a native or
delegated store, an acceptance record, a human disposition, or a
reconstruction, and it never dereferences any filesystem path carried by the
historical payload.  A future product transport slice owns the
server-allowlisted payload loader.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Callable

from admissible.delegated_gate.canonical import canonical_bytes, require_sha256
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
    create_historical_evaluation_pairing_authority,
    derive_historical_v5_evaluation_profile,
    validate_historical_evaluation_pairing_relation,
)
from admissible.delegated_gate.historical_evaluation_store import (
    HistoricalEvaluationArchiveConflict,
    HistoricalEvaluationArchiveDurabilityError,
    HistoricalEvaluationPairingBundle,
    HistoricalEvaluationStoreError,
    load_historical_evaluation_pairing,
    persist_historical_evaluation_pairing,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    CONFIRMATION_TAG_LENGTH,
    MAX_CONFIRMATION_SECRET_BYTES,
    MIN_CONFIRMATION_SECRET_BYTES,
    build_historical_pairing_confirmation_message,
    verify_historical_pairing_confirmation_tag,
)
from admissible.delegated_gate.historical_pairing_review import (
    # The three preparation-state labels are owned and published by the review
    # module.  They are bound to private aliases here so this coordinator's own
    # public constant surface keeps carrying exactly one outcome meaning.
    PREPARATION_STATE_CONFIRMATION_IN_PROGRESS as _STATE_CONFIRMATION_IN_PROGRESS,
    PREPARATION_STATE_CONSUMED as _STATE_CONSUMED,
    PREPARATION_STATE_READY_FOR_CONFIRMATION as _STATE_READY_FOR_CONFIRMATION,
    HistoricalEvaluationPairingOwnerReview,
    build_historical_evaluation_pairing_owner_review,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
)


# The single accepted success meaning.  The result deliberately never states
# whether the archive was published now or already held the same exact bytes:
# deciding that would need a pre-publication existence probe, and such a probe
# is racy and could never be an honest fact.
CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE = "CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE"

DEFAULT_PREPARATION_TTL_SECONDS = 900
MAX_PREPARATION_TTL_SECONDS = 86_400
DEFAULT_MAX_PREPARATIONS = 64
MAX_PREPARATION_CAPACITY = 4_096
MAX_PREPARATION_ID_ATTEMPTS = 8
MIN_PREPARATION_ID_LENGTH = 8
MAX_PREPARATION_ID_LENGTH = 64

_PREPARATION_ID = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.:-]{%d,%d}"
    % (MIN_PREPARATION_ID_LENGTH - 1, MAX_PREPARATION_ID_LENGTH - 1)
)

# One generic bounded rejection string.  A wrong tag, an unusable pinned
# authority, and any other verification-time refusal are indistinguishable here
# so no oracle about the configured secret can be built from the message.
CONFIRMATION_REJECTED_MESSAGE = "historical pairing confirmation was not accepted"

# Non-canonical, ordered proof-strength limitations.  This constant is never
# persisted and is part of no fingerprint; exact membership and ordering are
# pinned by tests so the stated boundary cannot be silently weakened.
HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS: tuple[str, ...] = (
    "acceptance means only that a valid deterministic tag for the pinned "
    "pairing authority was presented and that the exact complete archive is "
    "now loadable",
    "actor_id is an asserted identifier and is not authenticated by this "
    "coordinator",
    "the tag is a symmetric shared-secret message authentication code and is "
    "not a digital signature",
    "the construction is deterministic and carries no nonce, so acceptance "
    "does not prove fresh secret possession by the current operator",
    "this coordinator gates only the archive publications routed through it "
    "and enforces nothing about the rest of the process",
    "the accepted lower-level historical evaluation store remains callable "
    "directly by trusted internal code without any confirmation",
    "the three-document archive holds no confirmation receipt, record, "
    "timestamp, tag, tag hash, or other secret-derived material",
    "an existing archive therefore never proves that a tag was presented, and "
    "no read model may infer confirmation from archive existence alone",
    "this result does not state whether the archive was published now or "
    "already held the same exact bytes",
    "the configured secret stays reachable in coordinator memory for the "
    "coordinator lifetime and is not zeroized",
    "this coordinator says nothing about execution, evidence, source "
    "resolution, eligibility, obligation satisfaction, claim support, result "
    "admission, or ProductVerdict",
)


# ---------------------------------------------------------------------------
# Bounded error hierarchy.
#
# Every message below is a fixed literal.  No message carries the configured
# secret, a presented tag, an expected tag, an archive path, a complete
# canonical document, nested owner content, or a Python repr with a memory
# address.  Underlying causes are chained so a trusted caller keeps the detail
# without it entering the coordinator's own bounded string.
# ---------------------------------------------------------------------------


class HistoricalPairingWorkflowError(RuntimeError):
    """Base class for bounded historical pairing coordinator failures."""


class InvalidPairingCoordinatorConfiguration(HistoricalPairingWorkflowError):
    pass


class InvalidPairingPreparationRequest(HistoricalPairingWorkflowError):
    pass


class PairingPreparationCapacityExhausted(HistoricalPairingWorkflowError):
    pass


class PairingPreparationIdentifierUnavailable(HistoricalPairingWorkflowError):
    pass


class PairingPreparationNotFound(HistoricalPairingWorkflowError):
    pass


class PairingPreparationExpired(HistoricalPairingWorkflowError):
    pass


class PairingPreparationConsumed(HistoricalPairingWorkflowError):
    pass


class PairingPreparationInUse(HistoricalPairingWorkflowError):
    pass


class StalePairingAuthorityFingerprint(HistoricalPairingWorkflowError):
    pass


class MalformedPairingConfirmationTag(HistoricalPairingWorkflowError):
    pass


class PairingConfirmationRejected(HistoricalPairingWorkflowError):
    pass


class PairingArchiveConflict(HistoricalPairingWorkflowError):
    pass


class PairingArchiveWriteFailed(HistoricalPairingWorkflowError):
    pass


class PairingArchiveDurabilityUncertain(HistoricalPairingWorkflowError):
    pass


class PairingArchiveReloadFailed(HistoricalPairingWorkflowError):
    pass


class PairingArchiveContentMismatch(HistoricalPairingWorkflowError):
    pass


# ---------------------------------------------------------------------------
# Presentation-safe immutable views.
#
# None of these is canonical, fingerprinted, or persisted.  Deliberately none
# defines ``to_dict``: an ephemeral coordinator object must never be mistaken
# for an archive document.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HistoricalEvaluationPairingReviewProjection:
    """Read-only scalar projection derived from the pinned canonical objects.

    Only immutable identifiers, schema labels and owner-ordered member
    identities appear.  No filesystem path, no canonical mapping, no owner
    prose, and no secret-derived value is projected.
    """

    evaluation_profile_schema_version: str
    evaluation_profile_is_launchable: bool
    target_authorization_payload_schema_version: str
    pairing_authority_schema_version: str
    profile_id: str
    run_id: str
    session_id: str
    gate_id: str
    mission_id: str
    result_claim_ids: tuple[str, ...]
    verification_obligation_ids: tuple[str, ...]
    verification_evidence_binding_ids: tuple[str, ...]


@dataclass(frozen=True)
class HistoricalEvaluationPairingPreparationView:
    """Everything an independent caller needs to compute one confirmation tag.

    The configured secret, the expected tag, the pinned archive root, the
    pinned canonical mappings, the store, the registry lock, and the internal
    confirmation reservation state are all deliberately absent.
    ``confirmation_message`` is public material: it is exactly the Step 5C2A
    domain constant, one NUL separator, and the canonical authority bytes.
    """

    preparation_id: str
    asserted_actor_id: str
    authority_fingerprint: str
    evaluation_profile_fingerprint: str
    target_authorization_payload_fingerprint: str
    confirmation_message: bytes
    review_projection: HistoricalEvaluationPairingReviewProjection
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class HistoricalEvaluationPairingWorkflowResult:
    """One ephemeral, non-canonical confirmation outcome.

    ``archived_pairing`` is the completely reloaded accepted Step 5C1 bundle,
    not a coordinator-authored document.  The outcome states only that a valid
    deterministic tag was accepted and that the exact complete archive is now
    loadable.
    """

    outcome: str
    preparation_id: str
    asserted_actor_id: str
    authority_fingerprint: str
    evaluation_profile_fingerprint: str
    target_authorization_payload_fingerprint: str
    archived_pairing: HistoricalEvaluationPairingBundle
    limitations: tuple[str, ...]


@dataclass
class _PinnedPreparation:
    """Ephemeral in-memory pinning for exactly one prepared pairing.

    This object is internal, is never returned, is never fingerprinted, and is
    never persisted.  It deliberately has no ``to_dict``.
    """

    preparation_id: str
    evaluation_profile: NativeMissionProfile
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4
    pairing_authority: HistoricalEvaluationPairingAuthority
    confirmation_message: bytes
    archive_root: Path
    created_at: float
    confirmation_reserved: bool = field(default=False)
    consumed: bool = field(default=False)


# ---------------------------------------------------------------------------
# Bounded scalar validation.
# ---------------------------------------------------------------------------


def _validated_configured_secret(configured_secret: bytes) -> bytes:
    """Require exact bounded ``bytes`` and retain them completely unmodified.

    The accepted Step 5C2A bounds are reused verbatim.  Nothing here decodes,
    trims, normalizes, or re-encodes the configured secret, and no textual
    secret is ever converted.
    """

    if type(configured_secret) is not bytes:
        raise InvalidPairingCoordinatorConfiguration(
            "configured historical pairing confirmation secret must be exact bytes"
        )
    if not (
        MIN_CONFIRMATION_SECRET_BYTES
        <= len(configured_secret)
        <= MAX_CONFIRMATION_SECRET_BYTES
    ):
        raise InvalidPairingCoordinatorConfiguration(
            "configured historical pairing confirmation secret must be between "
            f"{MIN_CONFIRMATION_SECRET_BYTES} and {MAX_CONFIRMATION_SECRET_BYTES} "
            "bytes"
        )
    return configured_secret


def _validated_archive_root(archive_root: Path) -> Path:
    """Require one canonical absolute archive root without touching the disk."""

    if not isinstance(archive_root, Path):
        raise InvalidPairingCoordinatorConfiguration(
            "configured historical pairing archive root must be an explicit Path"
        )
    raw = os.fspath(archive_root)
    if (
        "\x00" in raw
        or not archive_root.is_absolute()
        or Path(os.path.abspath(raw)) != archive_root
    ):
        raise InvalidPairingCoordinatorConfiguration(
            "configured historical pairing archive root must be canonical and "
            "absolute"
        )
    return archive_root


def _validated_bound(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise InvalidPairingCoordinatorConfiguration(
            f"configured historical pairing {label} must be an integer in "
            f"[1, {maximum}]"
        )
    return value


def _validated_callable(value: object, *, label: str) -> Callable:
    if not callable(value):
        raise InvalidPairingCoordinatorConfiguration(
            f"configured historical pairing {label} must be callable"
        )
    return value


def _validated_preparation_id(preparation_id: str, *, label: str) -> str:
    if type(preparation_id) is not str or not _PREPARATION_ID.fullmatch(preparation_id):
        raise InvalidPairingPreparationRequest(
            f"historical pairing {label} must be a bounded opaque identifier of "
            f"{MIN_PREPARATION_ID_LENGTH} to {MAX_PREPARATION_ID_LENGTH} "
            "identifier characters"
        )
    return preparation_id


def _validated_expected_authority_fingerprint(expected: str) -> str:
    try:
        return require_sha256(expected, "expected authority fingerprint")
    except ValueError as exc:
        raise InvalidPairingPreparationRequest(
            "expected historical pairing authority fingerprint must be a "
            "lowercase SHA-256 digest"
        ) from exc


def _validated_presented_tag(presented_confirmation_tag: str) -> str:
    """Require exact Step 5C2A tag syntax before any secret is touched."""

    if (
        type(presented_confirmation_tag) is not str
        or len(presented_confirmation_tag) != CONFIRMATION_TAG_LENGTH
        or any(
            character not in "0123456789abcdef"
            for character in presented_confirmation_tag
        )
    ):
        raise MalformedPairingConfirmationTag(
            "presented historical pairing confirmation tag must be exactly "
            f"{CONFIRMATION_TAG_LENGTH} lowercase hexadecimal characters"
        )
    return presented_confirmation_tag


def _member_identities(members, attribute: str) -> tuple[str, ...]:
    return tuple(getattr(member, attribute) for member in members)


def _review_projection(
    *,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
    pairing_authority: HistoricalEvaluationPairingAuthority,
) -> HistoricalEvaluationPairingReviewProjection:
    return HistoricalEvaluationPairingReviewProjection(
        evaluation_profile_schema_version=evaluation_profile.schema_version,
        evaluation_profile_is_launchable=(
            evaluation_profile.is_launchable_runtime_profile
        ),
        target_authorization_payload_schema_version=(
            target_authorization_payload.schema_version
        ),
        pairing_authority_schema_version=pairing_authority.schema_version,
        profile_id=evaluation_profile.profile_id,
        run_id=evaluation_profile.run_id,
        session_id=evaluation_profile.session_id,
        gate_id=evaluation_profile.gate_id,
        mission_id=evaluation_profile.mission_id,
        result_claim_ids=_member_identities(
            evaluation_profile.claim_authority.claims, "claim_id"
        ),
        verification_obligation_ids=_member_identities(
            evaluation_profile.claim_verification_plan_authority
            .verification_obligations,
            "obligation_id",
        ),
        verification_evidence_binding_ids=_member_identities(
            evaluation_profile.verification_evidence_binding_authority.bindings,
            "binding_id",
        ),
    )


class HistoricalEvaluationPairingCoordinator:
    """Confirmation-gated, headless coordinator over the accepted primitives.

    The configured secret and the configured archive root are coordinator
    configuration.  Neither is ever supplied by a preparation request or by a
    confirmation request, neither is returned by any public method, and the
    secret is never logged, serialized, or persisted.

    The registry lock guards only the in-memory preparation registry.  No
    configurable callback -- neither the injected clock nor the injected
    identifier factory -- and no canonical derivation, validation, message
    construction, tag verification, archive publication, archive reload, or
    filesystem operation ever runs while that lock is held, so an injected
    callback cannot deadlock this coordinator merely by being invoked.
    """

    def __init__(
        self,
        *,
        configured_secret: bytes,
        archive_root: Path,
        preparation_ttl_seconds: int = DEFAULT_PREPARATION_TTL_SECONDS,
        max_preparations: int = DEFAULT_MAX_PREPARATIONS,
        clock: Callable[[], float] = time.monotonic,
        preparation_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._configured_secret = _validated_configured_secret(configured_secret)
        self._archive_root = _validated_archive_root(archive_root)
        self._preparation_ttl_seconds = _validated_bound(
            preparation_ttl_seconds,
            label="preparation TTL seconds",
            maximum=MAX_PREPARATION_TTL_SECONDS,
        )
        self._max_preparations = _validated_bound(
            max_preparations,
            label="preparation capacity",
            maximum=MAX_PREPARATION_CAPACITY,
        )
        self._clock = _validated_callable(clock, label="clock")
        self._preparation_id_factory = _validated_callable(
            preparation_id_factory, label="preparation identifier factory"
        )
        self._lock = threading.Lock()
        self._preparations: dict[str, _PinnedPreparation] = {}

    def __repr__(self) -> str:
        """Bounded repr without the secret, the archive root, or an address."""

        return "<HistoricalEvaluationPairingCoordinator>"

    # -- internal clock and registry -------------------------------------

    def _now(self) -> float:
        value = self._clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise InvalidPairingCoordinatorConfiguration(
                "configured historical pairing clock must return a finite number"
            )
        return float(value)

    def _is_expired(self, preparation: _PinnedPreparation, now: float) -> bool:
        """Fail closed, including when a supplied clock moves backwards."""

        elapsed = now - preparation.created_at
        return elapsed < 0.0 or elapsed >= float(self._preparation_ttl_seconds)

    def _sweep_locked(self, now: float, *, keep: str | None = None) -> None:
        """Drop expired unreserved preparations.  This persists nothing.

        ``keep`` protects the preparation a caller has just resolved so that an
        expired locator is refused as expired rather than silently degraded into
        a not-found answer by the sweep that runs alongside it.
        """

        for key in [
            key
            for key, preparation in self._preparations.items()
            if key != keep
            and not preparation.confirmation_reserved
            and self._is_expired(preparation, now)
        ]:
            del self._preparations[key]

    def _candidate_identifier(self) -> str:
        """Obtain and validate one candidate identifier outside the lock.

        The identifier factory is a public constructor parameter, so an injected
        callback may block, raise, inspect external state, acquire another lock,
        or re-enter this coordinator.  It is therefore never invoked while the
        registry lock is held, and neither is the configured clock.
        """

        candidate = self._preparation_id_factory()
        if type(candidate) is not str or not _PREPARATION_ID.fullmatch(candidate):
            raise InvalidPairingCoordinatorConfiguration(
                "configured historical pairing preparation identifier factory "
                "must return a bounded opaque identifier"
            )
        return candidate

    def _register_preparation(
        self,
        *,
        now: float,
        evaluation_profile: NativeMissionProfile,
        target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
        pairing_authority: HistoricalEvaluationPairingAuthority,
        confirmation_message: bytes,
    ) -> str:
        """Insert one complete preparation under a bounded candidate sequence.

        Every candidate is produced and validated outside the lock; the lock is
        then taken only to reclaim, to refuse on capacity, and to decide
        uniqueness atomically.  A colliding candidate releases the lock before
        the next candidate is requested, so no configurable callback ever runs
        under it.  The uniqueness decision itself stays inside the lock, so two
        simultaneous preparations offered the same candidate sequence can never
        both insert the same identifier, and a candidate is never reserved with
        a placeholder document.
        """

        for _attempt in range(MAX_PREPARATION_ID_ATTEMPTS):
            candidate = self._candidate_identifier()
            with self._lock:
                self._sweep_locked(now)
                if len(self._preparations) >= self._max_preparations:
                    # Consumed preparations can never be confirmed again, so they
                    # are reclaimed in insertion order before any refusal.
                    for key in [
                        key
                        for key, preparation in self._preparations.items()
                        if preparation.consumed
                        and not preparation.confirmation_reserved
                    ]:
                        del self._preparations[key]
                        if len(self._preparations) < self._max_preparations:
                            break
                if len(self._preparations) >= self._max_preparations:
                    raise PairingPreparationCapacityExhausted(
                        "historical pairing preparation capacity of "
                        f"{self._max_preparations} live preparations is exhausted"
                    )
                if candidate in self._preparations:
                    continue
                self._preparations[candidate] = _PinnedPreparation(
                    preparation_id=candidate,
                    evaluation_profile=evaluation_profile,
                    target_authorization_payload=target_authorization_payload,
                    pairing_authority=pairing_authority,
                    confirmation_message=confirmation_message,
                    archive_root=self._archive_root,
                    created_at=now,
                )
                return candidate
        raise PairingPreparationIdentifierUnavailable(
            "historical pairing preparation identifier could not be allocated "
            f"within {MAX_PREPARATION_ID_ATTEMPTS} bounded attempts"
        )

    # -- preparation ------------------------------------------------------

    def prepare_historical_evaluation_pairing(
        self,
        *,
        target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
        result_claims: object,
        claim_verification_plan: object,
        verification_evidence_bindings: object,
        actor_id: str,
    ) -> HistoricalEvaluationPairingPreparationView:
        """Pin one exact pairing and return its public confirmation material.

        Nothing is persisted, no filesystem path carried by the payload is
        dereferenced, and the configured secret is neither needed nor accessed.
        The preparation is registered only after every validation step below has
        already succeeded, so an invalid request leaves no preparation behind.
        """

        if not isinstance(
            target_authorization_payload, NativeCanaryAuthorizationPayloadV4
        ):
            raise InvalidPairingPreparationRequest(
                "historical pairing preparation requires an already-loaded exact "
                "canonical historical v4 authorization payload"
            )
        try:
            target_authorization_payload.validated_historical_structure()
        except (TypeError, ValueError) as exc:
            raise InvalidPairingPreparationRequest(
                "historical pairing preparation requires an already-loaded exact "
                "canonical historical v4 authorization payload"
            ) from exc

        try:
            evaluation_profile = derive_historical_v5_evaluation_profile(
                target_authorization_payload=target_authorization_payload,
                result_claims=result_claims,
                claim_verification_plan=claim_verification_plan,
                verification_evidence_bindings=verification_evidence_bindings,
            )
        except (TypeError, ValueError) as exc:
            raise InvalidPairingPreparationRequest(
                "historical pairing preparation could not derive the exact v5 "
                "evaluation profile from the supplied owner material"
            ) from exc

        if (
            evaluation_profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V5
            or evaluation_profile.is_launchable_runtime_profile
        ):
            raise InvalidPairingPreparationRequest(
                "derived historical evaluation profile must be exact v5 and must "
                "remain non-launchable"
            )

        try:
            pairing_authority = create_historical_evaluation_pairing_authority(
                actor_id=actor_id,
                evaluation_profile=evaluation_profile,
                target_authorization_payload=target_authorization_payload,
            )
        except (TypeError, ValueError) as exc:
            raise InvalidPairingPreparationRequest(
                "historical pairing preparation could not create the exact "
                "pairing authority for the asserted actor"
            ) from exc

        try:
            validate_historical_evaluation_pairing_relation(
                authority=pairing_authority,
                evaluation_profile=evaluation_profile,
                target_authorization_payload=target_authorization_payload,
            )
        except (TypeError, ValueError) as exc:
            raise InvalidPairingPreparationRequest(
                "historical pairing preparation relation between the derived "
                "profile and the historical payload is invalid"
            ) from exc

        try:
            confirmation_message = build_historical_pairing_confirmation_message(
                pairing_authority=pairing_authority
            )
        except (TypeError, ValueError) as exc:
            raise InvalidPairingPreparationRequest(
                "historical pairing confirmation message could not be built for "
                "the pinned authority"
            ) from exc

        projection = _review_projection(
            evaluation_profile=evaluation_profile,
            target_authorization_payload=target_authorization_payload,
            pairing_authority=pairing_authority,
        )

        now = self._now()
        preparation_id = self._register_preparation(
            now=now,
            evaluation_profile=evaluation_profile,
            target_authorization_payload=target_authorization_payload,
            pairing_authority=pairing_authority,
            confirmation_message=confirmation_message,
        )

        return HistoricalEvaluationPairingPreparationView(
            preparation_id=preparation_id,
            asserted_actor_id=pairing_authority.actor_id,
            authority_fingerprint=pairing_authority.authority_fingerprint,
            evaluation_profile_fingerprint=(
                pairing_authority.evaluation_profile_fingerprint
            ),
            target_authorization_payload_fingerprint=(
                pairing_authority.target_authorization_payload_fingerprint
            ),
            confirmation_message=confirmation_message,
            review_projection=projection,
            limitations=HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS,
        )

    # -- confirmation -----------------------------------------------------

    def _reserve(self, preparation_id: str) -> _PinnedPreparation:
        """Resolve one preparation and reserve it atomically under the lock."""

        now = self._now()
        with self._lock:
            self._sweep_locked(now, keep=preparation_id)
            preparation = self._preparations.get(preparation_id)
            if preparation is None:
                raise PairingPreparationNotFound(
                    "historical pairing preparation was not found"
                )
            if self._is_expired(preparation, now):
                if not preparation.confirmation_reserved:
                    del self._preparations[preparation_id]
                raise PairingPreparationExpired(
                    "historical pairing preparation has expired"
                )
            if preparation.consumed:
                raise PairingPreparationConsumed(
                    "historical pairing preparation was already consumed"
                )
            if preparation.confirmation_reserved:
                raise PairingPreparationInUse(
                    "historical pairing preparation is already being confirmed"
                )
            preparation.confirmation_reserved = True
            return preparation

    def _release(self, preparation: _PinnedPreparation, *, consumed: bool) -> None:
        with self._lock:
            if consumed:
                preparation.consumed = True
            preparation.confirmation_reserved = False

    def _persist(
        self, preparation: _PinnedPreparation
    ) -> HistoricalEvaluationPairingAuthority:
        """Publish the three pinned documents through the accepted store."""

        try:
            return persist_historical_evaluation_pairing(
                archive_root=preparation.archive_root,
                evaluation_profile=preparation.evaluation_profile,
                target_authorization_payload=(
                    preparation.target_authorization_payload
                ),
                pairing_authority=preparation.pairing_authority,
            )
        except HistoricalEvaluationArchiveConflict as exc:
            raise PairingArchiveConflict(
                "historical pairing archive already holds conflicting bytes for "
                "this pairing"
            ) from exc
        except HistoricalEvaluationArchiveDurabilityError as exc:
            raise PairingArchiveDurabilityUncertain(
                "historical pairing archive publication durability is uncertain"
            ) from exc
        except HistoricalEvaluationStoreError as exc:
            raise PairingArchiveWriteFailed(
                "historical pairing archive publication did not complete"
            ) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise PairingArchiveWriteFailed(
                "historical pairing archive publication did not complete"
            ) from exc

    def _reload(
        self, preparation: _PinnedPreparation
    ) -> HistoricalEvaluationPairingBundle:
        """Reload the complete archive through the accepted public load API."""

        try:
            return load_historical_evaluation_pairing(
                archive_root=preparation.archive_root,
                authority_fingerprint=(
                    preparation.pairing_authority.authority_fingerprint
                ),
            )
        except HistoricalEvaluationStoreError as exc:
            raise PairingArchiveReloadFailed(
                "historical pairing archive could not be completely reloaded"
            ) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise PairingArchiveReloadFailed(
                "historical pairing archive could not be completely reloaded"
            ) from exc

    @staticmethod
    def _require_exact_reloaded_bytes(
        preparation: _PinnedPreparation,
        reloaded: HistoricalEvaluationPairingBundle,
    ) -> HistoricalEvaluationPairingBundle:
        """Require the reloaded documents to equal the pinned objects exactly."""

        if not isinstance(reloaded, HistoricalEvaluationPairingBundle):
            raise PairingArchiveReloadFailed(
                "historical pairing archive could not be completely reloaded"
            )
        pinned = (
            preparation.evaluation_profile,
            preparation.target_authorization_payload,
            preparation.pairing_authority,
        )
        loaded = (
            reloaded.evaluation_profile,
            reloaded.target_authorization_payload,
            reloaded.pairing_authority,
        )
        try:
            comparisons = [
                (canonical_bytes(left.to_dict()), canonical_bytes(right.to_dict()))
                for left, right in zip(pinned, loaded)
            ]
        except (AttributeError, TypeError, ValueError) as exc:
            raise PairingArchiveContentMismatch(
                "reloaded historical pairing documents are not the exact pinned "
                "canonical bytes"
            ) from exc
        if any(expected != observed for expected, observed in comparisons):
            raise PairingArchiveContentMismatch(
                "reloaded historical pairing documents are not the exact pinned "
                "canonical bytes"
            )
        if reloaded.evaluation_profile.is_launchable_runtime_profile:
            raise PairingArchiveContentMismatch(
                "reloaded historical evaluation profile must remain non-launchable"
            )
        return reloaded

    def confirm_historical_evaluation_pairing(
        self,
        *,
        preparation_id: str,
        expected_authority_fingerprint: str,
        presented_confirmation_tag: str,
    ) -> HistoricalEvaluationPairingWorkflowResult:
        """Verify one independently supplied tag, then publish and reload.

        The API accepts a tag and never a secret.  This coordinator never
        computes the presented tag, never returns an expected tag, and never
        feeds a self-computed tag into its own verifier: verification is
        delegated to the accepted Step 5C2A helper with the configured secret,
        the pinned authority, and the caller's tag exactly as supplied.

        Nothing is written before verification succeeds.  On any failure the
        reservation is released and the preparation stays retryable until it
        expires; no tag is burned globally and no nonce or replay cache exists.
        """

        identifier = _validated_preparation_id(
            preparation_id, label="preparation identifier"
        )
        expected = _validated_expected_authority_fingerprint(
            expected_authority_fingerprint
        )

        preparation = self._reserve(identifier)
        consumed = False
        try:
            # Staleness is decided before the configured secret is reached, so a
            # caller holding an outdated authority never exercises the secret.
            if preparation.pairing_authority.authority_fingerprint != expected:
                raise StalePairingAuthorityFingerprint(
                    "expected historical pairing authority fingerprint does not "
                    "match the pinned preparation"
                )

            tag = _validated_presented_tag(presented_confirmation_tag)
            try:
                accepted = verify_historical_pairing_confirmation_tag(
                    configured_secret=self._configured_secret,
                    pairing_authority=preparation.pairing_authority,
                    presented_tag=tag,
                )
            except (TypeError, ValueError):
                raise PairingConfirmationRejected(
                    CONFIRMATION_REJECTED_MESSAGE
                ) from None
            if accepted is not True:
                raise PairingConfirmationRejected(CONFIRMATION_REJECTED_MESSAGE)

            self._persist(preparation)
            reloaded = self._require_exact_reloaded_bytes(
                preparation, self._reload(preparation)
            )
            consumed = True
        finally:
            self._release(preparation, consumed=consumed)

        return HistoricalEvaluationPairingWorkflowResult(
            outcome=CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE,
            preparation_id=preparation.preparation_id,
            asserted_actor_id=preparation.pairing_authority.actor_id,
            authority_fingerprint=(
                preparation.pairing_authority.authority_fingerprint
            ),
            evaluation_profile_fingerprint=(
                preparation.pairing_authority.evaluation_profile_fingerprint
            ),
            target_authorization_payload_fingerprint=(
                preparation.pairing_authority
                .target_authorization_payload_fingerprint
            ),
            archived_pairing=reloaded,
            limitations=HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS,
        )

    # -- review -----------------------------------------------------------

    @staticmethod
    def _preparation_state(preparation: _PinnedPreparation) -> str:
        """Report the in-memory snapshot state of one live preparation.

        A consumed preparation can never be confirmed again, so ``consumed``
        outranks the transient reservation flag.  This is process state only: it
        vanishes on restart and is never reconstructed from archive existence.
        """

        if preparation.consumed:
            return _STATE_CONSUMED
        if preparation.confirmation_reserved:
            return _STATE_CONFIRMATION_IN_PROGRESS
        return _STATE_READY_FOR_CONFIRMATION

    def get_historical_evaluation_pairing_review(
        self,
        *,
        preparation_id: str,
        expected_authority_fingerprint: str,
    ) -> HistoricalEvaluationPairingOwnerReview:
        """Return one complete, read-only owner review of a live preparation.

        The method reserves nothing, confirms nothing, reads no secret, extends
        no TTL, persists nothing, accesses no filesystem, and returns no mutable
        canonical object.  Consumed and in-progress preparations stay reviewable
        while they are still present; expired ones do not, and the expired
        answer is never degraded into a not-found answer.

        Only the snapshot is taken under the registry lock.  The complete review
        -- including the fresh exact compatibility revalidation -- is built after
        the lock is released, so no review work can block a concurrent
        preparation or confirmation.
        """

        identifier = _validated_preparation_id(
            preparation_id, label="preparation identifier"
        )
        expected = _validated_expected_authority_fingerprint(
            expected_authority_fingerprint
        )

        # The configured clock is a public constructor parameter and may block,
        # raise, or re-enter this coordinator, so it is called before the lock.
        now = self._now()
        with self._lock:
            self._sweep_locked(now, keep=identifier)
            preparation = self._preparations.get(identifier)
            if preparation is None:
                raise PairingPreparationNotFound(
                    "historical pairing preparation was not found"
                )
            if self._is_expired(preparation, now):
                if not preparation.confirmation_reserved:
                    del self._preparations[identifier]
                raise PairingPreparationExpired(
                    "historical pairing preparation has expired"
                )
            # The complete fingerprint is compared, never a prefix.
            if preparation.pairing_authority.authority_fingerprint != expected:
                raise StalePairingAuthorityFingerprint(
                    "expected historical pairing authority fingerprint does not "
                    "match the pinned preparation"
                )
            evaluation_profile = preparation.evaluation_profile
            target_authorization_payload = (
                preparation.target_authorization_payload
            )
            pairing_authority = preparation.pairing_authority
            confirmation_message = preparation.confirmation_message
            preparation_state = self._preparation_state(preparation)
            # ``created_at`` is deliberately untouched: reviewing never renews.

        return build_historical_evaluation_pairing_owner_review(
            preparation_id=identifier,
            preparation_state=preparation_state,
            evaluation_profile=evaluation_profile,
            target_authorization_payload=target_authorization_payload,
            pairing_authority=pairing_authority,
            confirmation_message=confirmation_message,
        )


__all__ = [
    "CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE",
    "CONFIRMATION_REJECTED_MESSAGE",
    "DEFAULT_MAX_PREPARATIONS",
    "DEFAULT_PREPARATION_TTL_SECONDS",
    "HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS",
    "HistoricalEvaluationPairingCoordinator",
    "HistoricalEvaluationPairingOwnerReview",
    "HistoricalEvaluationPairingPreparationView",
    "HistoricalEvaluationPairingReviewProjection",
    "HistoricalEvaluationPairingWorkflowResult",
    "HistoricalPairingWorkflowError",
    "InvalidPairingCoordinatorConfiguration",
    "InvalidPairingPreparationRequest",
    "MAX_PREPARATION_CAPACITY",
    "MAX_PREPARATION_ID_ATTEMPTS",
    "MAX_PREPARATION_ID_LENGTH",
    "MAX_PREPARATION_TTL_SECONDS",
    "MIN_PREPARATION_ID_LENGTH",
    "MalformedPairingConfirmationTag",
    "PairingArchiveConflict",
    "PairingArchiveContentMismatch",
    "PairingArchiveDurabilityUncertain",
    "PairingArchiveReloadFailed",
    "PairingArchiveWriteFailed",
    "PairingConfirmationRejected",
    "PairingPreparationCapacityExhausted",
    "PairingPreparationConsumed",
    "PairingPreparationExpired",
    "PairingPreparationIdentifierUnavailable",
    "PairingPreparationInUse",
    "PairingPreparationNotFound",
    "StalePairingAuthorityFingerprint",
]
