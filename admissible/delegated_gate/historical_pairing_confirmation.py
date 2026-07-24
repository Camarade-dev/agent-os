"""Deterministic shared-secret confirmation material for one exact pairing.

This module builds and verifies a domain-separated HMAC-SHA256 confirmation tag
over exactly one canonical ``HistoricalEvaluationPairingAuthority``.  It is a
pure cryptographic primitive: it validates the authority, serializes it
canonically, frames those bytes under one fixed domain constant, computes or
compares an HMAC tag, and returns.  It performs no filesystem, environment,
subprocess, Git, archive, evidence, product, or provider access, keeps no cache
or module-level mutable state, and persists nothing.

The tag proves only that a valid deterministic HMAC tag for one exact pairing
authority was presented under the configured local shared-secret mechanism.  The
construction has no nonce, so an earlier tag for the same authority can be
presented again; see ``HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS`` for the
complete ordered statement of what the mechanism does and does not establish.
"""

from __future__ import annotations

import hashlib
import hmac

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
)


HISTORICAL_PAIRING_CONFIRMATION_DOMAIN = (
    b"admissible_historical_evaluation_pairing_confirmation_v1"
)
# The single NUL byte is a framing separator, not padding: the domain constant
# contains no NUL, so no other domain and authority pair can produce the same
# concatenated message.
HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR = b"\x00"
# Bounds are explicit so a caller can never authenticate with an empty,
# accidentally truncated, or unbounded key.  The future coordinator owns the
# single encoding of a configured textual secret into these bytes; this module
# never normalizes, trims, decodes, or re-encodes what it is given.
MIN_CONFIRMATION_SECRET_BYTES = 16
MAX_CONFIRMATION_SECRET_BYTES = 4096
CONFIRMATION_TAG_LENGTH = 64

_TAG_CHARACTERS = frozenset("0123456789abcdef")

# Non-canonical, ordered proof-strength limitations.  This constant is not a
# persisted document and is not part of any canonical fingerprint; exact
# membership and ordering are pinned by tests so the stated boundary cannot be
# silently weakened.
HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS: tuple[str, ...] = (
    "a valid tag applies to exactly one pairing-authority canonical byte "
    "sequence and to no other authority",
    "actor_id is an asserted identifier and is not authenticated by this "
    "mechanism",
    "the tag is a symmetric shared-secret message authentication code and is "
    "not a digital signature",
    "the configured shared secret is not bound to any named actor",
    "the construction is deterministic and carries no nonce, so an earlier tag "
    "for the same authority can be replayed",
    "acceptance therefore does not prove fresh secret possession by the "
    "current operator",
    "this mechanism says nothing about execution, evidence, source resolution, "
    "eligibility, obligation satisfaction, claim support, result admission, or "
    "ProductVerdict",
    "the security of this mechanism depends on the entropy and the local "
    "confidentiality of the configured secret",
    "no secret, tag, hash of a tag, or other secret-derived material may be "
    "persisted",
)


def _validated_pairing_authority(
    pairing_authority: HistoricalEvaluationPairingAuthority,
) -> HistoricalEvaluationPairingAuthority:
    """Require the exact canonical authority type and revalidate it actively.

    The exact type is required rather than any subclass: a subclass could
    override ``to_dict`` and move the bytes under the tag away from the exact
    canonical document the tag is supposed to bind.
    """

    if type(pairing_authority) is not HistoricalEvaluationPairingAuthority:
        raise ValueError(
            "historical pairing confirmation requires an exact canonical "
            "HistoricalEvaluationPairingAuthority"
        )
    return pairing_authority.validated()


def _validated_secret(secret: bytes, label: str) -> bytes:
    """Require exact bounded ``bytes`` and return them completely unmodified."""

    if type(secret) is not bytes:
        raise ValueError(f"{label} must be exact bytes")
    if not secret:
        raise ValueError(f"{label} must be non-empty")
    if not (
        MIN_CONFIRMATION_SECRET_BYTES
        <= len(secret)
        <= MAX_CONFIRMATION_SECRET_BYTES
    ):
        raise ValueError(
            f"{label} must be between {MIN_CONFIRMATION_SECRET_BYTES} and "
            f"{MAX_CONFIRMATION_SECRET_BYTES} bytes"
        )
    return secret


def _validated_presented_tag(presented_tag: str) -> str:
    """Require exact lowercase 64-character hexadecimal tag syntax.

    Uppercase, padded, truncated, over-long, and non-hexadecimal tags are
    malformed syntax and raise; they are never repaired into a comparison.
    """

    if (
        type(presented_tag) is not str
        or len(presented_tag) != CONFIRMATION_TAG_LENGTH
        or any(character not in _TAG_CHARACTERS for character in presented_tag)
    ):
        raise ValueError(
            "presented historical pairing confirmation tag must be exactly "
            f"{CONFIRMATION_TAG_LENGTH} lowercase hexadecimal characters"
        )
    return presented_tag


def build_historical_pairing_confirmation_message(
    *,
    pairing_authority: HistoricalEvaluationPairingAuthority,
) -> bytes:
    """Frame one exact pairing authority as confirmation-message bytes.

    The message is exactly the domain constant, one NUL separator, and the
    canonical bytes of the complete authority document.  ``actor_id``, the V5
    evaluation-profile fingerprint, and the V4 authorization-payload
    fingerprint are therefore all bound transitively and none is repeated
    separately.  No archive root, path, product contract, preparation
    identifier, timestamp, nonce, runtime digest, evidence, or result value
    enters the message, and the secret never does.

    The returned bytes are neither a canonical authority nor a persisted
    document.
    """

    authority = _validated_pairing_authority(pairing_authority)
    return (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
        + HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR
        + canonical_bytes(authority.to_dict())
    )


def compute_historical_pairing_confirmation_tag(
    *,
    secret: bytes,
    pairing_authority: HistoricalEvaluationPairingAuthority,
) -> str:
    """Compute the deterministic HMAC-SHA256 confirmation tag for one authority.

    The secret is the HMAC key and never enters the confirmation message
    itself.  The result is exactly 64 lowercase hexadecimal characters and is
    deterministic for the same secret and the same authority bytes.
    """

    return hmac.new(
        key=_validated_secret(
            secret, "historical pairing confirmation secret"
        ),
        msg=build_historical_pairing_confirmation_message(
            pairing_authority=pairing_authority
        ),
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_historical_pairing_confirmation_tag(
    *,
    configured_secret: bytes,
    pairing_authority: HistoricalEvaluationPairingAuthority,
    presented_tag: str,
) -> bool:
    """Verify one presented tag against one exact authority in constant time.

    A correctly formed but incorrect tag returns ``False``.  Malformed tag
    syntax, a malformed secret, and a non-canonical authority raise a bounded
    ``ValueError``.  Neither the expected tag, the presented tag, nor any
    partial-match information is returned, logged, or persisted.
    """

    secret = _validated_secret(
        configured_secret, "configured historical pairing confirmation secret"
    )
    authority = _validated_pairing_authority(pairing_authority)
    candidate = _validated_presented_tag(presented_tag)
    expected = compute_historical_pairing_confirmation_tag(
        secret=secret,
        pairing_authority=authority,
    )
    return hmac.compare_digest(expected, candidate)


__all__ = [
    "CONFIRMATION_TAG_LENGTH",
    "HISTORICAL_PAIRING_CONFIRMATION_DOMAIN",
    "HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR",
    "HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS",
    "MAX_CONFIRMATION_SECRET_BYTES",
    "MIN_CONFIRMATION_SECRET_BYTES",
    "build_historical_pairing_confirmation_message",
    "compute_historical_pairing_confirmation_tag",
    "verify_historical_pairing_confirmation_tag",
]
