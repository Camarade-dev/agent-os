"""Bounded product-layer service for the historical evaluation pairing feature.

This module is the only place where the accepted startup-loaded payload
registry and the accepted confirmation-gated pairing coordinator are composed
into one object a transport may call.  It owns exactly those two collaborators
and nothing else: no HTTP request, no header, no CSRF state, no UI state, no
canonical mapping, no persistent preparation state of its own, and no tag
computer.

Every public operation returns one bounded ``(status, presentation)`` pair
following the existing product-launcher convention, so a transport never
inspects a domain exception and never decides a status code of its own.

The central transport law
-------------------------

The HTTP layer above this service must never become a source of canonical
authority.  Accordingly the request-facing operations here accept only a
``payload_id`` product locator, an asserted ``actor_id``, the raw owner-authored
member arrays exactly as the owner wrote them, a preparation identifier, a
complete expected authority fingerprint, and one independently generated
confirmation tag.  No V5 profile, V4 payload mapping, pairing authority,
canonical review object, archive root, filesystem path, configured secret,
expected tag, or evidence record is ever accepted from a caller.

Credential production stays outside the product
-----------------------------------------------

This module never computes a confirmation tag.  It does not import
``compute_historical_pairing_confirmation_tag``, does not import ``hmac`` or
``hashlib`` for credential generation, never accepts a raw presented secret, and
never returns an expected tag.  A trusted caller computes the tag independently
from the public confirmation-message bytes and the fixed recipe that the
accepted owner review already encodes.  Verification stays where it was
accepted: inside the coordinator, against the configured secret.

Deliberate, load-bearing limitations
------------------------------------

* The configured secret exists only inside the coordinator this service owns.
  Python ``bytes`` are immutable, so no zeroization is performed or claimed.
* The presented tag is never stored.  It exists only as a transient method
  argument for the duration of one confirmation call.
* Error mapping consults the exception's exact type and nothing else.  No
  ``str(exc)``, ``repr(exc)``, ``exc.args``, ``__cause__``, ``__context__``, or
  archive/store message ever reaches a response body.
* Nothing here authenticates an actor, proves fresh secret possession, produces
  a durable confirmation receipt, or infers confirmation from archive existence.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from admissible.delegated_gate.historical_pairing_workflow import (
    HistoricalEvaluationPairingCoordinator,
    HistoricalPairingWorkflowError,
    InvalidPairingPreparationRequest,
    MalformedPairingConfirmationTag,
    PairingArchiveConflict,
    PairingArchiveContentMismatch,
    PairingArchiveDurabilityUncertain,
    PairingArchiveReloadFailed,
    PairingArchiveWriteFailed,
    PairingConfirmationRejected,
    PairingPreparationCapacityExhausted,
    PairingPreparationConsumed,
    PairingPreparationExpired,
    PairingPreparationIdentifierUnavailable,
    PairingPreparationInUse,
    PairingPreparationNotFound,
    StalePairingAuthorityFingerprint,
)
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPairingConfiguration,
    HistoricalPayloadRegistry,
    HistoricalPayloadRegistryError,
)


# Every response code below is a fixed literal.  A response body is always
# exactly ``{"error": "<FIXED_CODE>"}`` on refusal: no message, detail, cause,
# owner input, fingerprint, tag, path, or exception text is ever added.
ERROR_PAYLOAD_NOT_ALLOWLISTED = "PAYLOAD_NOT_ALLOWLISTED"
ERROR_PAIRING_INPUTS_INVALID = "PAIRING_INPUTS_INVALID"
ERROR_PREPARATION_CAPACITY = "PREPARATION_CAPACITY"
ERROR_PREPARATION_IDENTIFIER_UNAVAILABLE = "PREPARATION_IDENTIFIER_UNAVAILABLE"
ERROR_PAIRING_LOCATOR_INVALID = "PAIRING_LOCATOR_INVALID"
ERROR_PREPARATION_NOT_FOUND = "PREPARATION_NOT_FOUND"
ERROR_PREPARATION_EXPIRED = "PREPARATION_EXPIRED"
ERROR_PREPARATION_CONSUMED = "PREPARATION_CONSUMED"
ERROR_PREPARATION_IN_USE = "PREPARATION_IN_USE"
ERROR_STALE_AUTHORITY_FINGERPRINT = "STALE_AUTHORITY_FINGERPRINT"
ERROR_CONFIRMATION_TAG_MALFORMED = "CONFIRMATION_TAG_MALFORMED"
ERROR_CONFIRMATION_REJECTED = "CONFIRMATION_REJECTED"
ERROR_ARCHIVE_CONFLICT = "ARCHIVE_CONFLICT"
ERROR_ARCHIVE_WRITE_FAILED = "ARCHIVE_WRITE_FAILED"
ERROR_ARCHIVE_DURABILITY_UNCERTAIN = "ARCHIVE_DURABILITY_UNCERTAIN"
ERROR_ARCHIVE_RELOAD_FAILED = "ARCHIVE_RELOAD_FAILED"
ERROR_ARCHIVE_CONTENT_MISMATCH = "ARCHIVE_CONTENT_MISMATCH"
ERROR_HISTORICAL_PAIRING_UNAVAILABLE = "HISTORICAL_PAIRING_UNAVAILABLE"

# One preparation is refused as a locator failure, an input failure, a capacity
# failure, or an identifier-allocation failure.  ``InvalidPairingPreparationRequest``
# means "the owner material could not be turned into an exact V5 pairing" here,
# and it means "the supplied locator is not well formed" on the review and
# confirmation paths, so the two mappings deliberately differ.
_PREPARATION_ERRORS: Mapping[type, tuple[int, str]] = {
    InvalidPairingPreparationRequest: (422, ERROR_PAIRING_INPUTS_INVALID),
    PairingPreparationCapacityExhausted: (429, ERROR_PREPARATION_CAPACITY),
    PairingPreparationIdentifierUnavailable: (
        503,
        ERROR_PREPARATION_IDENTIFIER_UNAVAILABLE,
    ),
}

_LOCATOR_ERRORS: Mapping[type, tuple[int, str]] = {
    InvalidPairingPreparationRequest: (400, ERROR_PAIRING_LOCATOR_INVALID),
    PairingPreparationNotFound: (404, ERROR_PREPARATION_NOT_FOUND),
    PairingPreparationExpired: (410, ERROR_PREPARATION_EXPIRED),
    PairingPreparationConsumed: (409, ERROR_PREPARATION_CONSUMED),
    PairingPreparationInUse: (409, ERROR_PREPARATION_IN_USE),
    StalePairingAuthorityFingerprint: (409, ERROR_STALE_AUTHORITY_FINGERPRINT),
}

_CONFIRMATION_ERRORS: Mapping[type, tuple[int, str]] = {
    # Every syntactically valid but incorrect credential -- a public authority
    # fingerprint, a runtime owner digest, a tag for another authority, a tag
    # under another secret -- reaches exactly this one code.
    MalformedPairingConfirmationTag: (400, ERROR_CONFIRMATION_TAG_MALFORMED),
    PairingConfirmationRejected: (403, ERROR_CONFIRMATION_REJECTED),
}

_ARCHIVE_ERRORS: Mapping[type, tuple[int, str]] = {
    PairingArchiveConflict: (409, ERROR_ARCHIVE_CONFLICT),
    PairingArchiveWriteFailed: (500, ERROR_ARCHIVE_WRITE_FAILED),
    PairingArchiveDurabilityUncertain: (500, ERROR_ARCHIVE_DURABILITY_UNCERTAIN),
    PairingArchiveReloadFailed: (500, ERROR_ARCHIVE_RELOAD_FAILED),
    PairingArchiveContentMismatch: (500, ERROR_ARCHIVE_CONTENT_MISMATCH),
}

PREPARATION_ERROR_MAPPING: Mapping[type, tuple[int, str]] = MappingProxyType(
    dict(_PREPARATION_ERRORS)
)
REVIEW_ERROR_MAPPING: Mapping[type, tuple[int, str]] = MappingProxyType(
    dict(_LOCATOR_ERRORS)
)
CONFIRMATION_ERROR_MAPPING: Mapping[type, tuple[int, str]] = MappingProxyType(
    {**_LOCATOR_ERRORS, **_CONFIRMATION_ERRORS, **_ARCHIVE_ERRORS}
)


class HistoricalPairingFeatureConfigurationError(RuntimeError):
    """One bounded refusal to construct the optional historical-pairing feature.

    Every message is a fixed literal.  None carries the configured secret, its
    length, the archive root, a configured document path, or payload content.
    """


def _mapped_refusal(
    exc: HistoricalPairingWorkflowError,
    mapping: Mapping[type, tuple[int, str]],
) -> tuple[int, dict[str, Any]]:
    """Map one bounded domain failure to a fixed status and fixed code.

    Only ``type(exc)`` is consulted.  The exception's message, arguments, cause,
    and context are never read, so no archive or store text, no owner input, no
    fingerprint, and no tag can leak through a refusal.  An unexpected member of
    the workflow hierarchy becomes one fixed unavailable code rather than
    anything more descriptive.
    """

    resolved = mapping.get(type(exc))
    if resolved is None:
        return 500, {"error": ERROR_HISTORICAL_PAIRING_UNAVAILABLE}
    status, code = resolved
    return status, {"error": code}


class HistoricalPairingService:
    """Bounded composition of one payload registry and one pairing coordinator.

    Construction performs the complete startup load: every configured document
    is opened exactly once by the registry, and a malformed configuration or
    document aborts construction before any caller can reach an operation.

    The service holds no HTTP object, no header, no CSRF state, no UI state, no
    canonical mapping, no preparation state of its own, and no tag computer.
    """

    def __init__(
        self,
        *,
        configuration: HistoricalPairingConfiguration,
        configured_secret: bytes,
    ) -> None:
        if type(configuration) is not HistoricalPairingConfiguration:
            raise HistoricalPairingFeatureConfigurationError(
                "historical pairing requires an exact "
                "HistoricalPairingConfiguration"
            )
        if type(configured_secret) is not bytes:
            raise HistoricalPairingFeatureConfigurationError(
                "historical pairing requires an exact bytes confirmation secret"
            )
        entries = configuration.payload_entries
        # A configuration declaring nothing is a configuration defect, never a
        # quiet equivalent of the feature being switched off.
        if not isinstance(entries, tuple) or not entries:
            raise HistoricalPairingFeatureConfigurationError(
                "historical pairing requires at least one configured payload "
                "entry"
            )
        self._registry = HistoricalPayloadRegistry(configuration=configuration)
        # The configured bytes are handed to the accepted coordinator exactly as
        # supplied: nothing here decodes, trims, normalizes, or re-encodes them,
        # and no textual-secret conversion exists in this slice.
        self._coordinator = HistoricalEvaluationPairingCoordinator(
            configured_secret=configured_secret,
            archive_root=configuration.archive_root,
            preparation_ttl_seconds=configuration.preparation_ttl_seconds,
            max_preparations=configuration.max_preparations,
        )

    def __repr__(self) -> str:
        """Fixed bounded repr with no path, secret, tag, count, or address."""

        return "<HistoricalPairingService>"

    # -- payload listing --------------------------------------------------

    def payloads(self) -> tuple[int, dict[str, Any]]:
        """List the configured payload records in exact declaration order.

        This reads the registry's pinned in-memory metadata, so it performs no
        filesystem access at all.  No configured document path and no archive
        root is exposed.
        """

        return 200, {
            "payloads": [
                {
                    "payload_id": record.payload_id,
                    "payload_fingerprint": record.payload_fingerprint,
                    "document_sha256": record.document_sha256,
                    "document_byte_length": record.document_byte_length,
                }
                for record in self._registry.metadata
            ]
        }

    # -- preparation and review -------------------------------------------

    def prepare(
        self,
        *,
        payload_id: str,
        actor_id: object,
        result_claims: object,
        claim_verification_plan: object,
        verification_evidence_bindings: object,
    ) -> tuple[int, dict[str, Any]]:
        """Prepare one pairing and answer with its complete owner review.

        The caller supplies only a product locator and its own raw owner-authored
        material; the exact payload object always comes from the registry.  The
        answering review is obtained from the coordinator's review API after the
        preparation exists, never assembled from the request, the registry
        record, or the preparation view.
        """

        try:
            payload = self._registry.get(payload_id=payload_id)
        except HistoricalPayloadRegistryError:
            # A malformed identifier and an unregistered identifier are
            # deliberately indistinguishable: the answer is one fixed code.
            return 404, {"error": ERROR_PAYLOAD_NOT_ALLOWLISTED}
        try:
            view = self._coordinator.prepare_historical_evaluation_pairing(
                target_authorization_payload=payload,
                result_claims=result_claims,
                claim_verification_plan=claim_verification_plan,
                verification_evidence_bindings=verification_evidence_bindings,
                actor_id=actor_id,
            )
        except HistoricalPairingWorkflowError as exc:
            return _mapped_refusal(exc, PREPARATION_ERROR_MAPPING)
        return self._reviewed(
            preparation_id=view.preparation_id,
            expected_authority_fingerprint=view.authority_fingerprint,
            status=201,
        )

    def review(
        self,
        *,
        preparation_id: str,
        expected_authority_fingerprint: str,
    ) -> tuple[int, dict[str, Any]]:
        """Answer with a freshly generated complete review presentation.

        The accepted review API reserves nothing, confirms nothing, reads no
        configured secret, extends no TTL, and persists nothing.
        """

        return self._reviewed(
            preparation_id=preparation_id,
            expected_authority_fingerprint=expected_authority_fingerprint,
            status=200,
        )

    def _reviewed(
        self,
        *,
        preparation_id: str,
        expected_authority_fingerprint: str,
        status: int,
    ) -> tuple[int, dict[str, Any]]:
        try:
            review = self._coordinator.get_historical_evaluation_pairing_review(
                preparation_id=preparation_id,
                expected_authority_fingerprint=expected_authority_fingerprint,
            )
        except HistoricalPairingWorkflowError as exc:
            return _mapped_refusal(exc, REVIEW_ERROR_MAPPING)
        # ``to_presentation_dict`` builds fresh containers on every call, so a
        # caller mutating this mapping can never reach a later review, the
        # coordinator, or the archive.
        return status, review.to_presentation_dict()

    # -- confirmation ------------------------------------------------------

    def confirm(
        self,
        *,
        preparation_id: str,
        expected_authority_fingerprint: str,
        presented_confirmation_tag: str,
    ) -> tuple[int, dict[str, Any]]:
        """Forward one independently generated tag to the accepted verifier.

        The tag is passed through exactly as received: nothing here strips,
        cases, decodes, trims, compares, hashes, logs, persists, or caches it,
        and it never becomes service state.  The coordinator remains the sole
        tag-syntax validator and the sole credential verifier.

        The success body reports bounded scalars only.  The reloaded archive
        bundle is never serialized, and the document count is observed from the
        bundle that was actually reloaded rather than asserted as a constant.
        """

        try:
            result = self._coordinator.confirm_historical_evaluation_pairing(
                preparation_id=preparation_id,
                expected_authority_fingerprint=expected_authority_fingerprint,
                presented_confirmation_tag=presented_confirmation_tag,
            )
        except HistoricalPairingWorkflowError as exc:
            return _mapped_refusal(exc, CONFIRMATION_ERROR_MAPPING)
        archived = result.archived_pairing
        documents = (
            archived.evaluation_profile,
            archived.target_authorization_payload,
            archived.pairing_authority,
        )
        return 200, {
            "outcome": result.outcome,
            "preparation_id": result.preparation_id,
            "asserted_actor_id": result.asserted_actor_id,
            "pairing_authority_fingerprint": result.authority_fingerprint,
            "evaluation_profile_fingerprint": (
                result.evaluation_profile_fingerprint
            ),
            "target_authorization_payload_fingerprint": (
                result.target_authorization_payload_fingerprint
            ),
            "archived_pairing_document_count": sum(
                1 for document in documents if document is not None
            ),
            "limitations": list(result.limitations),
        }


def build_historical_pairing_service(
    *,
    configuration: HistoricalPairingConfiguration | None,
    configured_secret: bytes | None,
) -> HistoricalPairingService | None:
    """Decide the optional feature from two separate optional inputs.

    Both absent means the feature is off and no registry, coordinator, service,
    or route exists.  Both present builds the complete service, performing the
    whole startup document load here so a malformed document aborts before any
    socket exists.  Exactly one present is a configuration defect and is refused
    loudly rather than silently degraded into a disabled feature.
    """

    if configuration is None and configured_secret is None:
        return None
    if configuration is None or configured_secret is None:
        raise HistoricalPairingFeatureConfigurationError(
            "historical pairing requires both a configuration and a configured "
            "secret, or neither"
        )
    return HistoricalPairingService(
        configuration=configuration,
        configured_secret=configured_secret,
    )


__all__ = [
    "CONFIRMATION_ERROR_MAPPING",
    "ERROR_ARCHIVE_CONFLICT",
    "ERROR_ARCHIVE_CONTENT_MISMATCH",
    "ERROR_ARCHIVE_DURABILITY_UNCERTAIN",
    "ERROR_ARCHIVE_RELOAD_FAILED",
    "ERROR_ARCHIVE_WRITE_FAILED",
    "ERROR_CONFIRMATION_REJECTED",
    "ERROR_CONFIRMATION_TAG_MALFORMED",
    "ERROR_HISTORICAL_PAIRING_UNAVAILABLE",
    "ERROR_PAIRING_INPUTS_INVALID",
    "ERROR_PAIRING_LOCATOR_INVALID",
    "ERROR_PAYLOAD_NOT_ALLOWLISTED",
    "ERROR_PREPARATION_CAPACITY",
    "ERROR_PREPARATION_CONSUMED",
    "ERROR_PREPARATION_EXPIRED",
    "ERROR_PREPARATION_IDENTIFIER_UNAVAILABLE",
    "ERROR_PREPARATION_IN_USE",
    "ERROR_PREPARATION_NOT_FOUND",
    "ERROR_STALE_AUTHORITY_FINGERPRINT",
    "HistoricalPairingFeatureConfigurationError",
    "HistoricalPairingService",
    "PREPARATION_ERROR_MAPPING",
    "REVIEW_ERROR_MAPPING",
    "build_historical_pairing_service",
]
