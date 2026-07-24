"""Step 5C2A: pure domain-separated HMAC confirmation for one exact pairing.

Every expected cryptographic value in this module is an independently computed
literal.  The production helpers are never used to produce an expectation they
are then compared against.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import hmac
import inspect
import io
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType
from unittest import mock

import pytest

from admissible.delegated_gate import historical_pairing_confirmation as confirmation
from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.historical_evaluation import (
    HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION,
    HistoricalEvaluationPairingAuthority,
    create_historical_evaluation_pairing_authority,
    project_v5_runtime_authority_to_v2,
)
from admissible.delegated_gate.historical_evaluation_store import (
    AUTHORITY_DIRECTORY_NAME,
    AUTHORITY_FILE_SUFFIX,
    PAYLOAD_DIRECTORY_NAME,
    PAYLOAD_FILE_SUFFIX,
    PROFILE_DIRECTORY_NAME,
    PROFILE_FILE_SUFFIX,
    load_historical_evaluation_pairing,
    persist_historical_evaluation_pairing,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    CONFIRMATION_TAG_LENGTH,
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN,
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR,
    HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS,
    MAX_CONFIRMATION_SECRET_BYTES,
    MIN_CONFIRMATION_SECRET_BYTES,
    build_historical_pairing_confirmation_message,
    compute_historical_pairing_confirmation_tag,
    verify_historical_pairing_confirmation_tag,
)
from admissible.delegated_gate.mission_profile import (
    FLAGSHIP_INCIDENT_REPLAY_PROFILE,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    OWNER_AUTHORIZATION_DIGEST_ENV,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from test_admissible_claim_authority_v3 import _profile as _v3_profile
from test_admissible_claim_verification_plan_v4 import _profile as _v4_profile
from test_admissible_historical_evaluation_pairing import _refingerprint_payload
from test_admissible_historical_v5_derivation import _derive, _runtime_v2_profile
from test_admissible_verification_evidence_binding_v5 import _profile as _v5_profile
from test_admissible_workflow_recovery_profile import _payload_harness


# ---------------------------------------------------------------------------
# Independently computed vector.
#
# The authority document, its canonical bytes, the framed message and the HMAC
# tag below were produced outside this repository by a standalone script that
# re-implements the documented canonical-JSON rule (sorted keys, compact
# separators, no ASCII escaping, UTF-8) and calls the standard library directly.
# ``from_dict`` re-validates the pinned ``authority_fingerprint``, so a wrong
# literal cannot silently pass.
# ---------------------------------------------------------------------------

VECTOR_SECRET = b"historical-pairing-confirmation-vector-secret"
VECTOR_OTHER_SECRET = b"historical-pairing-confirmation-other-secret"

VECTOR_AUTHORITY_DOCUMENT = {
    "schema_version": "admissible_historical_evaluation_pairing_authority_v1",
    "actor_id": "owner.asserted-actor",
    "evaluation_profile_fingerprint": "a1" * 32,
    "target_authorization_payload_fingerprint": "b2" * 32,
    "authority_fingerprint": (
        "e9f86652070b248a03af3ad46c2eea7a9f6db6ef078034aad16f82c0b9d0000a"
    ),
}

VECTOR_AUTHORITY_BYTES = (
    b'{"actor_id":"owner.asserted-actor","authority_fingerprint":"e9f86652070b'
    b'248a03af3ad46c2eea7a9f6db6ef078034aad16f82c0b9d0000a","evaluation_profil'
    b'e_fingerprint":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
    b'a1a1a1a1","schema_version":"admissible_historical_evaluation_pairing_aut'
    b'hority_v1","target_authorization_payload_fingerprint":"b2b2b2b2b2b2b2b2b'
    b'2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"}'
)

VECTOR_MESSAGE = (
    b"admissible_historical_evaluation_pairing_confirmation_v1"
    b"\x00"
    b'{"actor_id":"owner.asserted-actor","authority_fingerprint":"e9f86652070b'
    b'248a03af3ad46c2eea7a9f6db6ef078034aad16f82c0b9d0000a","evaluation_profil'
    b'e_fingerprint":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
    b'a1a1a1a1","schema_version":"admissible_historical_evaluation_pairing_aut'
    b'hority_v1","target_authorization_payload_fingerprint":"b2b2b2b2b2b2b2b2b'
    b'2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"}'
)

VECTOR_TAG = "9c6454bb1e9020f271bfd730d8fbeee72aef58450e0e7aea3181a55e0a95da46"
VECTOR_OTHER_SECRET_TAG = (
    "c9c3dd6017ad49623e079f2db69152055c5e1b8993eafc5b54423afc3976fb6e"
)

# Same secret, one field changed in the bound authority.
VECTOR_OTHER_ACTOR_DOCUMENT = {
    **VECTOR_AUTHORITY_DOCUMENT,
    "actor_id": "owner.other-actor",
    "authority_fingerprint": (
        "324c49b26f01c850135d62e6cebf65383fcfed42e307275d191f67d7781f76c2"
    ),
}
VECTOR_OTHER_ACTOR_TAG = (
    "2cf785bcbdd2b254abdf617af7199dfd893e25f64eff53a71941acf4f4ced313"
)

VECTOR_OTHER_V5_DOCUMENT = {
    **VECTOR_AUTHORITY_DOCUMENT,
    "evaluation_profile_fingerprint": "c3" * 32,
    "authority_fingerprint": (
        "12e42c54f0612988b2385e74c19d730afa0f163216184f4879f9b3504b723198"
    ),
}
VECTOR_OTHER_V5_TAG = (
    "5b27202d56d22998e8087a168b92b0d9929503d2f89c385c616a06d601b6562d"
)

VECTOR_OTHER_V4_DOCUMENT = {
    **VECTOR_AUTHORITY_DOCUMENT,
    "target_authorization_payload_fingerprint": "d4" * 32,
    "authority_fingerprint": (
        "9b55a3bdf2d84c644859dc941b8a453d904d6ccb1f2e8f437bcbe58bf870553f"
    ),
}
VECTOR_OTHER_V4_TAG = (
    "4365c10620f4501bf1158543942c4878d159f584a664725fc7af316d45a536dc"
)

# Rejected constructions over the same secret and the same authority bytes.
REJECTED_CONSTRUCTION_TAGS = {
    "no_domain": "969d2cdfb73ba1cf52d629ec0d30656514a9b9c0c2536385b6a8f0bb07c04284",
    "no_separator": "8e87684fc06c9a6cb647ff2dd63b4bcd9751d7734ba9a86676a18f26c07161c0",
    "domain_after_authority": (
        "7dc9f7d7499337c5024cfc8858ba063ac601a1cf1f2cf903d919a828756e0433"
    ),
    "other_domain": "24883193be57de432d40aeb69591671e56e56bc8a2fa900491e31096c8fc310c",
    "raw_sha256_concatenation": (
        "95e0acf88a3f2ff3288b1b3ec03a32eb0a7e5c575a5287970958b55fc8d175db"
    ),
    "runtime_owner_digest_formula": (
        "76a946410a2ab01f9ce27bc77368ea72f8380f34530ce37e4275531fe03a12a2"
    ),
}


@pytest.fixture(scope="module")
def vector_authority() -> HistoricalEvaluationPairingAuthority:
    return HistoricalEvaluationPairingAuthority.from_dict(
        deepcopy(VECTOR_AUTHORITY_DOCUMENT)
    )


# ---------------------------------------------------------------------------
# Real Step 5B/5C1 pairing, reused for compatibility and replay evidence.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def historical_pairing(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[
    NativeMissionProfile,
    NativeCanaryAuthorizationPayloadV4,
    HistoricalEvaluationPairingAuthority,
]:
    # The label deliberately avoids the words scanned for in the archive
    # documents below, so the fixture path can never satisfy those checks.
    fixture_root = tmp_path_factory.mktemp("step-5c2a-fixture")
    runtime_profile = _runtime_v2_profile()
    live = _payload_harness(fixture_root, runtime_profile).payload.to_dict()
    absent = fixture_root / "absent-original-material"
    live["source_repository"] = str(absent / "source")
    live["executable"] = str(absent / "bin" / "agent.exe")
    live["launcher_prefix"] = [
        str(absent / "bin" / f"launcher-{index}.exe")
        for index, _value in enumerate(live["launcher_prefix"])
    ]
    run_root = absent / runtime_profile.run_id
    live["run_root"] = str(run_root)
    live["workspace_root"] = str(run_root / WORKSPACE_DIRECTORY_NAME)
    live["evidence_root"] = str(run_root / EVIDENCE_DIRECTORY_NAME)
    live["native_sidecar_root"] = str(
        run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME
    )
    payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(live)
    )
    profile = _derive(payload)
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.asserted-actor",
        evaluation_profile=profile,
        target_authorization_payload=payload,
    )
    assert not absent.exists()
    return profile, payload, authority


@pytest.fixture(scope="module")
def real_authority(historical_pairing) -> HistoricalEvaluationPairingAuthority:
    return historical_pairing[2]


REAL_SECRET = b"historical-pairing-confirmation-real-secret-material"


def _independent_tag(secret: bytes, authority_document: dict) -> str:
    """Recompute a tag without touching the production module.

    Only the documented canonical-JSON rule and the standard library are used,
    so this helper is an independent oracle rather than a re-export of the code
    under test.
    """

    body = json.dumps(
        authority_document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(
        key=secret,
        msg=b"admissible_historical_evaluation_pairing_confirmation_v1"
        + b"\x00"
        + body,
        digestmod=hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Exact framing.
# ---------------------------------------------------------------------------


def test_domain_constant_is_exact_bytes():
    assert HISTORICAL_PAIRING_CONFIRMATION_DOMAIN == (
        b"admissible_historical_evaluation_pairing_confirmation_v1"
    )
    assert isinstance(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN, bytes)
    assert HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR == b"\x00"
    assert b"\x00" not in HISTORICAL_PAIRING_CONFIRMATION_DOMAIN


def test_confirmation_message_is_the_exact_pinned_byte_sequence(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    message = build_historical_pairing_confirmation_message(
        pairing_authority=vector_authority
    )
    assert message == VECTOR_MESSAGE
    assert isinstance(message, bytes)
    assert len(message) == 466


def test_confirmation_message_is_domain_then_nul_then_canonical_authority(
    vector_authority: HistoricalEvaluationPairingAuthority,
    real_authority: HistoricalEvaluationPairingAuthority,
):
    for authority in (vector_authority, real_authority):
        message = build_historical_pairing_confirmation_message(
            pairing_authority=authority
        )
        authority_bytes = canonical_bytes(authority.to_dict())
        assert message == (
            HISTORICAL_PAIRING_CONFIRMATION_DOMAIN + b"\x00" + authority_bytes
        )
        assert message.startswith(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN)
        assert message[len(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN)] == 0
        assert message[len(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN) + 1 :] == (
            authority_bytes
        )
        assert message.count(b"\x00") == 1
    assert canonical_bytes(vector_authority.to_dict()) == VECTOR_AUTHORITY_BYTES


def test_message_binds_actor_id_and_both_document_identities(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    message = build_historical_pairing_confirmation_message(
        pairing_authority=vector_authority
    )
    assert b'"actor_id":"owner.asserted-actor"' in message
    assert (b'"evaluation_profile_fingerprint":"' + b"a1" * 32 + b'"') in message
    assert (
        b'"target_authorization_payload_fingerprint":"' + b"b2" * 32 + b'"'
    ) in message
    assert (
        b'"authority_fingerprint":"'
        + VECTOR_AUTHORITY_DOCUMENT["authority_fingerprint"].encode("ascii")
        + b'"'
    ) in message
    # The identities are bound exactly once, transitively through the canonical
    # authority bytes -- never appended a second time as separate material.
    for field, value in VECTOR_AUTHORITY_DOCUMENT.items():
        assert message.count(f'"{field}":'.encode("utf-8")) == 1
        assert message.count(value.encode("utf-8")) == 1


def test_message_ignores_dictionary_insertion_order(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    reversed_document = {
        key: VECTOR_AUTHORITY_DOCUMENT[key]
        for key in reversed(list(VECTOR_AUTHORITY_DOCUMENT))
    }
    assert list(reversed_document) != list(VECTOR_AUTHORITY_DOCUMENT)
    reordered = HistoricalEvaluationPairingAuthority.from_dict(reversed_document)
    assert (
        build_historical_pairing_confirmation_message(pairing_authority=reordered)
        == VECTOR_MESSAGE
    )
    assert compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=reordered
    ) == compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=vector_authority
    )


def test_message_excludes_archive_root_and_every_unrelated_context(
    historical_pairing,
    real_authority: HistoricalEvaluationPairingAuthority,
    tmp_path: Path,
):
    profile, payload, _authority = historical_pairing
    message = build_historical_pairing_confirmation_message(
        pairing_authority=real_authority
    )
    archive_root = tmp_path / "archive"
    for absent in (
        str(archive_root).encode("utf-8"),
        b"archive_root",
        str(payload.run_root).encode("utf-8"),
        str(payload.source_repository).encode("utf-8"),
        payload.source_head.encode("utf-8"),
        payload.payload_fingerprint.encode("utf-8"),
        profile.profile_fingerprint.encode("utf-8"),
        b"product_contract_id",
        b"preparation",
        b"nonce",
        b"timestamp",
        b"confirmed_at",
        b"evidence",
        b"ProductVerdict",
        REAL_SECRET,
    ):
        if absent in (
            payload.payload_fingerprint.encode("utf-8"),
            profile.profile_fingerprint.encode("utf-8"),
        ):
            # Those two appear only as the fingerprints already carried inside
            # the canonical authority, never as separate appended material.
            assert message.count(absent) == 1
            continue
        assert absent not in message
    # Exactly the authority bytes follow the framed domain.
    assert message == (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
        + b"\x00"
        + canonical_bytes(real_authority.to_dict())
    )


def test_message_requires_the_exact_authority_type_and_validates_it(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    with pytest.raises(ValueError, match="exact canonical"):
        build_historical_pairing_confirmation_message(
            pairing_authority=VECTOR_AUTHORITY_DOCUMENT  # type: ignore[arg-type]
        )

    class Subclass(HistoricalEvaluationPairingAuthority):
        pass

    with pytest.raises(ValueError, match="exact canonical"):
        build_historical_pairing_confirmation_message(
            pairing_authority=Subclass(**dict(vector_authority.__dict__))
        )
    tampered = HistoricalEvaluationPairingAuthority(
        **{**vector_authority.__dict__, "actor_id": "owner.tampered"}
    )
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        build_historical_pairing_confirmation_message(pairing_authority=tampered)
    with mock.patch.object(
        HistoricalEvaluationPairingAuthority,
        "validated",
        autospec=True,
        side_effect=AssertionError("canonical validation was not called"),
    ):
        with pytest.raises(AssertionError, match="canonical validation"):
            build_historical_pairing_confirmation_message(
                pairing_authority=vector_authority
            )


# ---------------------------------------------------------------------------
# Independent HMAC vector.
# ---------------------------------------------------------------------------


def test_tag_matches_the_independent_hmac_vector(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    tag = compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=vector_authority
    )
    assert tag == VECTOR_TAG
    assert tag == _independent_tag(VECTOR_SECRET, VECTOR_AUTHORITY_DOCUMENT)
    assert isinstance(tag, str)
    assert len(tag) == CONFIRMATION_TAG_LENGTH == 64
    assert tag == tag.lower()
    assert set(tag) <= set("0123456789abcdef")


def test_tag_is_deterministic_for_the_same_secret_and_authority(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    repeated = {
        compute_historical_pairing_confirmation_tag(
            secret=bytes(VECTOR_SECRET), pairing_authority=vector_authority
        )
        for _ in range(5)
    }
    assert repeated == {VECTOR_TAG}
    rebuilt = HistoricalEvaluationPairingAuthority.from_dict(
        deepcopy(VECTOR_AUTHORITY_DOCUMENT)
    )
    assert rebuilt is not vector_authority
    assert (
        compute_historical_pairing_confirmation_tag(
            secret=VECTOR_SECRET, pairing_authority=rebuilt
        )
        == VECTOR_TAG
    )


def test_a_different_secret_produces_a_different_tag(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    other = compute_historical_pairing_confirmation_tag(
        secret=VECTOR_OTHER_SECRET, pairing_authority=vector_authority
    )
    assert other == VECTOR_OTHER_SECRET_TAG
    assert other != VECTOR_TAG


@pytest.mark.parametrize(
    ("document", "expected_tag"),
    [
        (VECTOR_OTHER_ACTOR_DOCUMENT, VECTOR_OTHER_ACTOR_TAG),
        (VECTOR_OTHER_V5_DOCUMENT, VECTOR_OTHER_V5_TAG),
        (VECTOR_OTHER_V4_DOCUMENT, VECTOR_OTHER_V4_TAG),
    ],
    ids=["actor_id", "evaluation_profile_fingerprint", "payload_fingerprint"],
)
def test_every_bound_identity_change_produces_a_different_tag(
    document: dict,
    expected_tag: str,
):
    authority = HistoricalEvaluationPairingAuthority.from_dict(deepcopy(document))
    tag = compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=authority
    )
    assert tag == expected_tag
    assert tag == _independent_tag(VECTOR_SECRET, document)
    assert tag != VECTOR_TAG


def test_a_completely_different_authority_produces_a_different_tag(
    vector_authority: HistoricalEvaluationPairingAuthority,
    real_authority: HistoricalEvaluationPairingAuthority,
):
    assert canonical_bytes(real_authority.to_dict()) != VECTOR_AUTHORITY_BYTES
    vector_tag = compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=vector_authority
    )
    real_tag = compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=real_authority
    )
    assert real_tag == _independent_tag(VECTOR_SECRET, real_authority.to_dict())
    assert real_tag != vector_tag


# ---------------------------------------------------------------------------
# Secret handling.
# ---------------------------------------------------------------------------


def test_secret_bounds_are_exact_and_enforced(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    assert (MIN_CONFIRMATION_SECRET_BYTES, MAX_CONFIRMATION_SECRET_BYTES) == (
        16,
        4096,
    )
    for accepted in (b"s" * 16, b"s" * 4096):
        assert len(
            compute_historical_pairing_confirmation_tag(
                secret=accepted, pairing_authority=vector_authority
            )
        ) == 64
    for rejected in (b"", b"s" * 15, b"s" * 4097, b"s" * 65536):
        with pytest.raises(ValueError, match="secret must"):
            compute_historical_pairing_confirmation_tag(
                secret=rejected, pairing_authority=vector_authority
            )
        with pytest.raises(ValueError, match="secret must"):
            verify_historical_pairing_confirmation_tag(
                configured_secret=rejected,
                pairing_authority=vector_authority,
                presented_tag=VECTOR_TAG,
            )


@pytest.mark.parametrize(
    "secret",
    [
        "historical-pairing-confirmation-vector-secret",
        bytearray(VECTOR_SECRET),
        memoryview(VECTOR_SECRET),
        None,
        1234567890123456,
    ],
    ids=["str", "bytearray", "memoryview", "none", "int"],
)
def test_non_bytes_secrets_are_rejected(
    secret,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    with pytest.raises(ValueError, match="must be exact bytes"):
        compute_historical_pairing_confirmation_tag(
            secret=secret, pairing_authority=vector_authority
        )
    with pytest.raises(ValueError, match="must be exact bytes"):
        verify_historical_pairing_confirmation_tag(
            configured_secret=secret,
            pairing_authority=vector_authority,
            presented_tag=VECTOR_TAG,
        )


def test_secret_bytes_are_never_normalized_trimmed_or_re_encoded(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    base = b"  historical-pairing-secret-with-edges  "
    variants = {
        "exact": base,
        "stripped": base.strip(),
        "upper": base.upper(),
        "nul_prefixed": b"\x00" + base,
        "crlf": base + b"\r\n",
        "nfc_like": base + b"\xc3\xa9",
        "nfd_like": base + b"e\xcc\x81",
    }
    tags = {
        label: compute_historical_pairing_confirmation_tag(
            secret=secret, pairing_authority=vector_authority
        )
        for label, secret in variants.items()
    }
    assert len(set(tags.values())) == len(variants)
    # Trailing NUL bytes on a sub-block-size key are absorbed by HMAC's own
    # zero-padding of the key to the SHA-256 block size.  That equality is a
    # property of HMAC, not normalization performed here: whitespace stripping,
    # case folding and every other edit above do change the tag.
    assert (
        compute_historical_pairing_confirmation_tag(
            secret=base + b"\x00", pairing_authority=vector_authority
        )
        == tags["exact"]
    )
    assert tags["stripped"] != tags["exact"]
    # A verification configured with the exact secret accepts only the tag made
    # from those exact bytes.
    for label, tag in tags.items():
        assert verify_historical_pairing_confirmation_tag(
            configured_secret=base,
            pairing_authority=vector_authority,
            presented_tag=tag,
        ) is (label == "exact")


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------


def test_correct_tag_verifies_and_a_valid_format_wrong_tag_returns_false(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    assert (
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=VECTOR_TAG,
        )
        is True
    )
    wrong_but_well_formed = (
        "0" * 64,
        "f" * 64,
        VECTOR_OTHER_SECRET_TAG,
        VECTOR_OTHER_ACTOR_TAG,
        VECTOR_TAG[:-1] + ("0" if VECTOR_TAG[-1] != "0" else "1"),
    )
    for candidate in wrong_but_well_formed:
        assert len(candidate) == 64
        assert (
            verify_historical_pairing_confirmation_tag(
                configured_secret=VECTOR_SECRET,
                pairing_authority=vector_authority,
                presented_tag=candidate,
            )
            is False
        )


@pytest.mark.parametrize(
    "malformed",
    [
        VECTOR_TAG.upper(),
        VECTOR_TAG[:32] + VECTOR_TAG[32:].upper(),
        VECTOR_TAG[:63],
        VECTOR_TAG + "0",
        " " + VECTOR_TAG[1:],
        VECTOR_TAG + " ",
        " " + VECTOR_TAG,
        "\t" + VECTOR_TAG[1:],
        VECTOR_TAG[:-1] + "g",
        VECTOR_TAG[:-1] + "\n",
        "0x" + VECTOR_TAG[2:],
        "",
    ],
    ids=[
        "uppercase",
        "mixed-case",
        "short",
        "long",
        "leading-space-same-length",
        "trailing-space",
        "leading-space",
        "tab",
        "non-hex",
        "newline",
        "hex-prefix",
        "empty",
    ],
)
def test_malformed_tag_syntax_raises_a_bounded_value_error(
    malformed: str,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    with pytest.raises(ValueError, match="lowercase hexadecimal characters"):
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=malformed,
        )


@pytest.mark.parametrize(
    "presented",
    [None, 1234, b"a" * 64, bytearray(b"a" * 64), ["a" * 64]],
    ids=["none", "int", "bytes", "bytearray", "list"],
)
def test_non_string_tags_are_rejected(
    presented,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    with pytest.raises(ValueError, match="lowercase hexadecimal characters"):
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=presented,
        )


def test_verification_uses_hmac_compare_digest_and_not_equality(
    monkeypatch: pytest.MonkeyPatch,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    calls: list[tuple[str, str]] = []
    real_compare = hmac.compare_digest

    def observed(left, right):
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(confirmation.hmac, "compare_digest", observed)
    assert (
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=VECTOR_TAG,
        )
        is True
    )
    assert calls == [(VECTOR_TAG, VECTOR_TAG)]

    # The returned decision must come from the constant-time comparison itself:
    # an `==` substitute would still report True here.
    monkeypatch.setattr(confirmation.hmac, "compare_digest", lambda left, right: False)
    assert (
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=VECTOR_TAG,
        )
        is False
    )
    monkeypatch.setattr(confirmation.hmac, "compare_digest", lambda left, right: True)
    assert (
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag="0" * 64,
        )
        is True
    )


def test_verification_source_contains_no_equality_comparison_of_tags():
    source = inspect.getsource(verify_historical_pairing_confirmation_tag)
    assert "hmac.compare_digest(expected, candidate)" in source
    assert "expected ==" not in source
    assert "== candidate" not in source
    assert "!=" not in source


def test_verification_reveals_nothing_beyond_the_boolean(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    near_miss = VECTOR_TAG[:63] + ("0" if VECTOR_TAG[63] != "0" else "1")
    far_miss = "0" * 64
    outcomes = {
        candidate: verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=candidate,
        )
        for candidate in (near_miss, far_miss)
    }
    assert outcomes == {near_miss: False, far_miss: False}
    assert all(result is False for result in outcomes.values())
    signature = inspect.signature(verify_historical_pairing_confirmation_tag)
    assert signature.return_annotation == "bool"
    assert list(signature.parameters) == [
        "configured_secret",
        "pairing_authority",
        "presented_tag",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )


def test_verification_rejects_a_non_canonical_or_wrong_typed_authority(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    with pytest.raises(ValueError, match="exact canonical"):
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=VECTOR_AUTHORITY_DOCUMENT,  # type: ignore[arg-type]
            presented_tag=VECTOR_TAG,
        )
    tampered = HistoricalEvaluationPairingAuthority(
        **{**vector_authority.__dict__, "evaluation_profile_fingerprint": "c" * 64}
    )
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=tampered,
            presented_tag=VECTOR_TAG,
        )


# ---------------------------------------------------------------------------
# Domain separation.
# ---------------------------------------------------------------------------


def test_runtime_owner_digest_formula_does_not_verify_as_a_pairing_tag(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    # Exactly the committed runtime owner-authorization construction:
    # sha256(secret + b"\0" + canonical payload bytes).
    runtime_style = hashlib.sha256(
        VECTOR_SECRET + b"\0" + canonical_bytes(vector_authority.to_dict())
    ).hexdigest()
    assert runtime_style == REJECTED_CONSTRUCTION_TAGS["runtime_owner_digest_formula"]
    assert runtime_style != VECTOR_TAG
    assert (
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=runtime_style,
        )
        is False
    )


@pytest.mark.parametrize("construction", sorted(REJECTED_CONSTRUCTION_TAGS))
def test_every_rejected_construction_fails_verification(
    construction: str,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    candidate = REJECTED_CONSTRUCTION_TAGS[construction]
    assert candidate != VECTOR_TAG
    assert (
        verify_historical_pairing_confirmation_tag(
            configured_secret=VECTOR_SECRET,
            pairing_authority=vector_authority,
            presented_tag=candidate,
        )
        is False
    )


def test_partial_material_bindings_do_not_verify(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    """A tag over any single field must never satisfy the whole-authority tag."""

    partial_materials = {
        "actor_id_only": VECTOR_AUTHORITY_DOCUMENT["actor_id"],
        "authority_fingerprint_only": VECTOR_AUTHORITY_DOCUMENT[
            "authority_fingerprint"
        ],
        "evaluation_profile_fingerprint_only": VECTOR_AUTHORITY_DOCUMENT[
            "evaluation_profile_fingerprint"
        ],
        "target_payload_fingerprint_only": VECTOR_AUTHORITY_DOCUMENT[
            "target_authorization_payload_fingerprint"
        ],
    }
    seen = set()
    for label, material in partial_materials.items():
        for framed in (
            material.encode("utf-8"),
            HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
            + b"\x00"
            + material.encode("utf-8"),
        ):
            candidate = hmac.new(
                key=VECTOR_SECRET, msg=framed, digestmod=hashlib.sha256
            ).hexdigest()
            seen.add(candidate)
            assert candidate != VECTOR_TAG, label
            assert (
                verify_historical_pairing_confirmation_tag(
                    configured_secret=VECTOR_SECRET,
                    pairing_authority=vector_authority,
                    presented_tag=candidate,
                )
                is False
            )
    assert len(seen) == 2 * len(partial_materials)


def test_a_tag_for_one_authority_never_verifies_for_a_different_one(
    vector_authority: HistoricalEvaluationPairingAuthority,
    real_authority: HistoricalEvaluationPairingAuthority,
):
    others = [
        HistoricalEvaluationPairingAuthority.from_dict(deepcopy(document))
        for document in (
            VECTOR_OTHER_ACTOR_DOCUMENT,
            VECTOR_OTHER_V5_DOCUMENT,
            VECTOR_OTHER_V4_DOCUMENT,
        )
    ] + [real_authority]
    for other in others:
        assert (
            verify_historical_pairing_confirmation_tag(
                configured_secret=VECTOR_SECRET,
                pairing_authority=other,
                presented_tag=VECTOR_TAG,
            )
            is False
        )
        foreign_tag = compute_historical_pairing_confirmation_tag(
            secret=VECTOR_SECRET, pairing_authority=other
        )
        assert (
            verify_historical_pairing_confirmation_tag(
                configured_secret=VECTOR_SECRET,
                pairing_authority=vector_authority,
                presented_tag=foreign_tag,
            )
            is False
        )


# ---------------------------------------------------------------------------
# Replay semantics.
# ---------------------------------------------------------------------------


def test_the_same_tag_verifies_repeatedly_as_deterministic_replay(
    real_authority: HistoricalEvaluationPairingAuthority,
):
    captured = compute_historical_pairing_confirmation_tag(
        secret=REAL_SECRET, pairing_authority=real_authority
    )
    assert [
        verify_historical_pairing_confirmation_tag(
            configured_secret=REAL_SECRET,
            pairing_authority=real_authority,
            presented_tag=captured,
        )
        for _ in range(4)
    ] == [True, True, True, True]
    # Nothing in the mechanism can distinguish a replayed capture from a fresh
    # computation, which is exactly what the limitations state.
    assert captured == compute_historical_pairing_confirmation_tag(
        secret=REAL_SECRET, pairing_authority=real_authority
    )
    replay_limitations = [
        text
        for text in HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS
        if "replayed" in text or "fresh secret possession" in text
    ]
    assert len(replay_limitations) == 2
    assert "deterministic and carries no nonce" in replay_limitations[0]
    assert "does not prove fresh secret possession" in replay_limitations[1]


def test_a_replayed_tag_fails_for_every_distinct_authority(
    real_authority: HistoricalEvaluationPairingAuthority,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    captured = compute_historical_pairing_confirmation_tag(
        secret=REAL_SECRET, pairing_authority=real_authority
    )
    distinct = HistoricalEvaluationPairingAuthority.from_dict(
        {
            **real_authority.to_dict(),
            "actor_id": "owner.replaying-other-actor",
            "authority_fingerprint": fingerprint(
                {
                    **{
                        key: value
                        for key, value in real_authority.to_dict().items()
                        if key != "authority_fingerprint"
                    },
                    "actor_id": "owner.replaying-other-actor",
                }
            ),
        }
    )
    for other in (distinct, vector_authority):
        assert (
            verify_historical_pairing_confirmation_tag(
                configured_secret=REAL_SECRET,
                pairing_authority=other,
                presented_tag=captured,
            )
            is False
        )


# ---------------------------------------------------------------------------
# Proof-strength limitations.
# ---------------------------------------------------------------------------


EXPECTED_LIMITATIONS = (
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


def test_limitations_are_exact_ordered_and_immutable():
    assert HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS == EXPECTED_LIMITATIONS
    assert isinstance(HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS, tuple)
    assert len(HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS) == 9
    assert len(set(HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS)) == 9
    assert all(
        isinstance(text, str) and text == text.strip() and text
        for text in HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS
    )


@pytest.mark.parametrize(
    ("index", "required"),
    [
        (0, "exactly one pairing-authority canonical byte sequence"),
        (1, "is not authenticated"),
        (2, "is not a digital signature"),
        (3, "not bound to any named actor"),
        (4, "can be replayed"),
        (5, "does not prove fresh secret possession"),
        (6, "says nothing about execution, evidence, source resolution"),
        (7, "entropy and the local confidentiality of the configured secret"),
        (8, "no secret, tag, hash of a tag"),
    ],
)
def test_every_required_limitation_is_stated_in_order(index: int, required: str):
    assert required in HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS[index]


def test_limitation_seven_names_every_excluded_authority_surface():
    clause = HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS[6]
    for surface in (
        "execution",
        "evidence",
        "source resolution",
        "eligibility",
        "obligation satisfaction",
        "claim support",
        "result admission",
        "ProductVerdict",
    ):
        assert surface in clause


_POSITIVE_CLAIM_TOKENS = (
    "authenticated",
    "verified owner",
    "verified actor",
    "cryptographically signed",
    "digital signature",
    "fresh secret possession",
    "signer identity",
    "proves possession",
)
_NEGATION_TOKENS = ("not", "never", "no", "nothing", "cannot", "without", "only")


def _clauses(text: str) -> list[str]:
    """Split prose into clauses so a negation is checked where it applies.

    This is deliberately not a lexical ban: a token may appear as long as its
    own clause carries an explicit negation, so "actor_id ... is not
    authenticated" passes while "an authenticated actor" does not.
    """

    normalized = " ".join(text.lower().split())
    clauses: list[str] = []
    for sentence in re.split(r"[.;:]", normalized):
        clauses.extend(
            re.split(r",|\band\b|\bso\b|\btherefore\b|\bbecause\b|\bthat\b", sentence)
        )
    return clauses


def _positive_claim_violations(text: str) -> list[str]:
    violations = []
    for clause in _clauses(text):
        words = set(re.findall(r"[a-z_]+", clause))
        if words & set(_NEGATION_TOKENS):
            continue
        for token in _POSITIVE_CLAIM_TOKENS:
            if token in clause:
                violations.append(f"{token!r} in {clause.strip()!r}")
    return violations


def test_negation_aware_scanner_accepts_negations_and_rejects_positive_claims():
    assert _positive_claim_violations("actor_id is not authenticated.") == []
    assert _positive_claim_violations("the tag is not a digital signature.") == []
    assert (
        _positive_claim_violations(
            "acceptance does not prove fresh secret possession by the operator."
        )
        == []
    )
    assert _positive_claim_violations("the authenticated owner approved this.")
    assert _positive_claim_violations("this record is cryptographically signed.")
    assert _positive_claim_violations("fresh secret possession is established here")


def test_module_prose_makes_no_positive_authentication_claim():
    source = Path(inspect.getfile(confirmation)).read_text(encoding="utf-8")
    assert _positive_claim_violations(source) == []
    assert (
        _positive_claim_violations(
            "\n".join(HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS)
        )
        == []
    )
    for banned in (
        "authenticated owner",
        "authenticated actor",
        "verified owner",
        "cryptographically signed",
        "fresh secret possession proven",
        "proves fresh secret possession",
    ):
        assert banned not in source.lower()


# ---------------------------------------------------------------------------
# No receipt, no persistence, no secret-derived record.
# ---------------------------------------------------------------------------


def _module_tree() -> ast.Module:
    return ast.parse(
        Path(inspect.getfile(confirmation)).read_text(encoding="utf-8"),
        filename="historical_pairing_confirmation.py",
    )


def _imported_names() -> set[str]:
    """Names bound by an import rather than defined by this module."""

    names: set[str] = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
    return names


def test_module_defines_no_class_and_therefore_no_receipt_object():
    tree = _module_tree()
    assert [
        node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    ] == []
    assert [
        name
        for name, value in vars(confirmation).items()
        if isinstance(value, type)
        and not name.startswith("__")
        and getattr(value, "__module__", None) == confirmation.__name__
    ] == []


@pytest.mark.parametrize(
    "forbidden",
    [
        "HistoricalPairingConfirmationReceipt",
        "CONFIRMATION_RECEIPT_SCHEMA_VERSION",
        "HistoricalPairingConfirmationReceiptStore",
        "persist_historical_pairing_confirmation",
        "load_historical_pairing_confirmation",
        "confirmed_at",
        "confirmation_method",
        "confirmation_context",
        "CONFIRMATION_RECEIPT_DIRECTORY_NAME",
        "CONFIRMATION_RECEIPT_FILE_SUFFIX",
    ],
)
def test_no_receipt_symbol_exists(forbidden: str):
    assert not hasattr(confirmation, forbidden)
    assert forbidden not in confirmation.__all__


def test_no_receipt_schema_string_exists():
    source = Path(inspect.getfile(confirmation)).read_text(encoding="utf-8")
    string_literals = [
        node.value
        for node in ast.walk(_module_tree())
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))
    ]
    joined = " ".join(
        value if isinstance(value, str) else value.decode("utf-8", "replace")
        for value in string_literals
    ).lower()
    for schema_marker in (
        "confirmation_receipt",
        "pairing_confirmation_receipt",
        "_receipt_v",
        "confirmed_at",
        "confirmation_method",
        "confirmation_context",
    ):
        assert schema_marker not in joined
    # The only schema-shaped literal is the confirmation domain constant.
    assert source.count('b"admissible_historical_evaluation_pairing_confirmation_v1"') == 1


def test_module_imports_are_exactly_the_pure_allowed_set():
    imported: set[str] = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported == {
        "__future__",
        "hashlib",
        "hmac",
        "admissible.delegated_gate.canonical",
        "admissible.delegated_gate.historical_evaluation",
    }


@pytest.mark.parametrize(
    "forbidden_module",
    [
        "admissible.delegated_gate.historical_evaluation_store",
        "admissible.delegated_gate.native_executor",
        "admissible.delegated_gate.native_acceptance",
        "admissible.delegated_gate.native_canary",
        "admissible.delegated_gate.checkpoint",
        "admissible.delegated_gate.store",
        "admissible.delegated_gate.durability",
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.review_surface",
        "admissible.browser_runtime",
        "os",
        "pathlib",
        "subprocess",
        "json",
        "logging",
        "time",
        "datetime",
        "uuid",
        "secrets",
        "random",
    ],
)
def test_module_does_not_reference_any_forbidden_dependency(forbidden_module: str):
    source = Path(inspect.getfile(confirmation)).read_text(encoding="utf-8")
    tree = _module_tree()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != forbidden_module for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "") != forbidden_module
    assert not hasattr(confirmation, forbidden_module.rsplit(".", 1)[-1])
    del source


def test_public_surface_is_exactly_the_declared_api():
    assert confirmation.__all__ == [
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
    imported = _imported_names()
    assert imported == {
        "annotations",
        "hashlib",
        "hmac",
        "canonical_bytes",
        "HistoricalEvaluationPairingAuthority",
    }
    public = {
        name
        for name in vars(confirmation)
        if not name.startswith("_")
        and name not in imported
        and not isinstance(vars(confirmation)[name], ModuleType)
    }
    assert public == set(confirmation.__all__)


def test_module_level_state_is_immutable_and_never_caches_secret_material(
    vector_authority: HistoricalEvaluationPairingAuthority,
    real_authority: HistoricalEvaluationPairingAuthority,
):
    def snapshot() -> dict[str, str]:
        return {
            name: repr(value)
            for name, value in vars(confirmation).items()
            if not name.startswith("__")
        }

    before = snapshot()
    for authority, secret in (
        (vector_authority, VECTOR_SECRET),
        (real_authority, REAL_SECRET),
    ):
        tag = compute_historical_pairing_confirmation_tag(
            secret=secret, pairing_authority=authority
        )
        verify_historical_pairing_confirmation_tag(
            configured_secret=secret,
            pairing_authority=authority,
            presented_tag=tag,
        )
    after = snapshot()
    assert after == before
    mutable = {
        name: value
        for name, value in vars(confirmation).items()
        if isinstance(value, (dict, list, set, bytearray))
        and not name.startswith("__")
    }
    assert mutable == {}
    for name in confirmation.__all__:
        value = getattr(confirmation, name)
        if callable(value):
            assert value.__closure__ is None
            assert not hasattr(value, "cache_info")
            assert vars(value) == {}


def test_invoking_the_module_writes_no_file_and_touches_no_environment(
    tmp_path: Path,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    root = tmp_path / "observed"
    root.mkdir()
    before = sorted(path.name for path in root.iterdir())
    cwd_before = sorted(Path.cwd().iterdir())
    environment_before = dict(os.environ)
    tag = compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=vector_authority
    )
    verify_historical_pairing_confirmation_tag(
        configured_secret=VECTOR_SECRET,
        pairing_authority=vector_authority,
        presented_tag=tag,
    )
    assert sorted(path.name for path in root.iterdir()) == before == []
    assert sorted(Path.cwd().iterdir()) == cwd_before
    assert dict(os.environ) == environment_before
    for path in tmp_path.rglob("*"):
        assert tag not in path.name
        assert VECTOR_SECRET.decode("ascii") not in path.name


def test_reimporting_the_module_creates_no_effect_and_stays_deterministic(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    import importlib

    reloaded = importlib.reload(confirmation)
    assert (
        reloaded.compute_historical_pairing_confirmation_tag(
            secret=VECTOR_SECRET, pairing_authority=vector_authority
        )
        == VECTOR_TAG
    )
    assert (
        reloaded.HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS == EXPECTED_LIMITATIONS
    )
    assert reloaded.HISTORICAL_PAIRING_CONFIRMATION_DOMAIN == (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
    )


# ---------------------------------------------------------------------------
# Inertness and resource non-access.
# ---------------------------------------------------------------------------


class _ForbiddenEnvironment(dict):
    def __getitem__(self, key):
        raise AssertionError(f"confirmation read environment variable {key!r}")

    def get(self, key, default=None):
        raise AssertionError(f"confirmation read environment variable {key!r}")

    def __setitem__(self, key, value):
        raise AssertionError(f"confirmation wrote environment variable {key!r}")


def test_confirmation_performs_no_io_process_or_store_access(
    vector_authority: HistoricalEvaluationPairingAuthority,
    real_authority: HistoricalEvaluationPairingAuthority,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture,
):
    forbidden = AssertionError("historical pairing confirmation reached a resource")
    spies = (
        mock.patch.object(builtins, "open", side_effect=forbidden),
        mock.patch.object(io, "open", side_effect=forbidden),
        mock.patch.object(os, "open", side_effect=forbidden),
        mock.patch.object(os, "getenv", side_effect=forbidden),
        mock.patch.object(os, "environ", _ForbiddenEnvironment()),
        mock.patch.object(os, "remove", side_effect=forbidden),
        mock.patch.object(os, "replace", side_effect=forbidden),
        mock.patch.object(os, "makedirs", side_effect=forbidden),
        mock.patch.object(subprocess, "run", side_effect=forbidden),
        mock.patch.object(subprocess, "Popen", side_effect=forbidden),
        mock.patch.object(subprocess, "check_output", side_effect=forbidden),
        mock.patch.object(subprocess, "check_call", side_effect=forbidden),
        mock.patch.object(Path, "open", side_effect=forbidden),
        mock.patch.object(Path, "read_bytes", side_effect=forbidden),
        mock.patch.object(Path, "read_text", side_effect=forbidden),
        mock.patch.object(Path, "write_bytes", side_effect=forbidden),
        mock.patch.object(Path, "write_text", side_effect=forbidden),
        mock.patch.object(Path, "mkdir", side_effect=forbidden),
        mock.patch.object(Path, "stat", side_effect=forbidden),
        mock.patch.object(Path, "exists", side_effect=forbidden),
        mock.patch.object(Path, "iterdir", side_effect=forbidden),
        mock.patch.object(Path, "unlink", side_effect=forbidden),
    )
    tracked_prefixes = (
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.review_surface",
        "admissible.delegated_gate.native_acceptance",
        "admissible.delegated_gate.native_executor",
        "admissible.delegated_gate.historical_evaluation_store",
        "admissible.delegated_gate.checkpoint",
    )
    tags: list[str] = []
    with caplog.at_level(logging.DEBUG):
        with ExitStack() as stack:
            for spy in spies:
                stack.enter_context(spy)
            for authority, secret in (
                (vector_authority, VECTOR_SECRET),
                (real_authority, REAL_SECRET),
            ):
                build_historical_pairing_confirmation_message(
                    pairing_authority=authority
                )
                tag = compute_historical_pairing_confirmation_tag(
                    secret=secret, pairing_authority=authority
                )
                tags.append(tag)
                assert (
                    verify_historical_pairing_confirmation_tag(
                        configured_secret=secret,
                        pairing_authority=authority,
                        presented_tag=tag,
                    )
                    is True
                )
    # No secret or tag was logged or printed anywhere.
    emitted = "\n".join(record.getMessage() for record in caplog.records)
    captured = capsys.readouterr()
    for leak in tags + [
        VECTOR_SECRET.decode("ascii"),
        REAL_SECRET.decode("ascii"),
    ]:
        assert leak not in emitted
        assert leak not in captured.out
        assert leak not in captured.err
    del tracked_prefixes


def test_importing_and_invoking_pulls_in_no_product_or_store_module(
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    tracked = (
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.review_surface",
        "admissible.browser_runtime",
        "admissible.delegated_gate.native_acceptance",
    )
    module_source = Path(inspect.getfile(confirmation)).read_text(encoding="utf-8")
    for prefix in tracked:
        assert prefix not in module_source
    before = {name for name in sys.modules if name.startswith(tracked)}
    compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=vector_authority
    )
    after = {name for name in sys.modules if name.startswith(tracked)}
    assert after == before


# ---------------------------------------------------------------------------
# Historical compatibility.
# ---------------------------------------------------------------------------


def test_all_canonical_profiles_and_payloads_remain_byte_identical(
    historical_pairing,
    vector_authority: HistoricalEvaluationPairingAuthority,
):
    profile, payload, authority = historical_pairing
    objects = (
        FLAGSHIP_INCIDENT_REPLAY_PROFILE,
        project_v5_runtime_authority_to_v2(profile),
        _v3_profile(),
        _v4_profile(),
        _v5_profile(),
        profile,
    )
    before_bytes = tuple(canonical_bytes(item.to_dict()) for item in objects)
    before_fingerprints = tuple(item.profile_fingerprint for item in objects)
    before_launchable = tuple(item.is_launchable_runtime_profile for item in objects)
    payload_bytes = canonical_bytes(payload.to_dict())
    payload_fingerprint = payload.payload_fingerprint
    authority_bytes = canonical_bytes(authority.to_dict())
    authority_fingerprint = authority.authority_fingerprint

    tag = compute_historical_pairing_confirmation_tag(
        secret=REAL_SECRET, pairing_authority=authority
    )
    assert verify_historical_pairing_confirmation_tag(
        configured_secret=REAL_SECRET,
        pairing_authority=authority,
        presented_tag=tag,
    )
    compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET, pairing_authority=vector_authority
    )

    assert tuple(canonical_bytes(item.to_dict()) for item in objects) == before_bytes
    assert tuple(item.profile_fingerprint for item in objects) == before_fingerprints
    assert (
        tuple(item.is_launchable_runtime_profile for item in objects)
        == before_launchable
    )
    assert canonical_bytes(payload.to_dict()) == payload_bytes
    assert payload.payload_fingerprint == payload_fingerprint
    assert canonical_bytes(authority.to_dict()) == authority_bytes
    assert authority.authority_fingerprint == authority_fingerprint
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert profile.is_launchable_runtime_profile is False


def test_step_5c1_archive_bytes_and_exact_replay_are_unchanged(
    tmp_path: Path,
    historical_pairing,
):
    profile, payload, authority = historical_pairing
    archive_root = tmp_path / "a"
    persist_historical_evaluation_pairing(
        archive_root=archive_root,
        evaluation_profile=profile,
        target_authorization_payload=payload,
        pairing_authority=authority,
    )
    documents = sorted(
        path for path in archive_root.rglob("*") if path.is_file()
    )
    assert sorted(path.name for path in documents) == sorted(
        [
            f"{authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}",
            f"{payload.payload_fingerprint}{PAYLOAD_FILE_SUFFIX}",
            f"{profile.profile_fingerprint}{PROFILE_FILE_SUFFIX}",
        ]
    )
    assert {path.parent.name for path in documents} == {
        AUTHORITY_DIRECTORY_NAME,
        PAYLOAD_DIRECTORY_NAME,
        PROFILE_DIRECTORY_NAME,
    }
    before = {path: path.read_bytes() for path in documents}

    tag = compute_historical_pairing_confirmation_tag(
        secret=REAL_SECRET, pairing_authority=authority
    )
    assert verify_historical_pairing_confirmation_tag(
        configured_secret=REAL_SECRET,
        pairing_authority=authority,
        presented_tag=tag,
    )

    # The archive is still exactly three documents with identical bytes and the
    # create-only replay is still byte-idempotent.
    after_paths = sorted(path for path in archive_root.rglob("*") if path.is_file())
    assert after_paths == documents
    assert {path: path.read_bytes() for path in after_paths} == before
    replayed = persist_historical_evaluation_pairing(
        archive_root=archive_root,
        evaluation_profile=profile,
        target_authorization_payload=payload,
        pairing_authority=authority,
    )
    assert replayed == authority
    assert sorted(
        path for path in archive_root.rglob("*") if path.is_file()
    ) == documents
    assert {path: path.read_bytes() for path in documents} == before
    for blob in before.values():
        assert tag.encode("ascii") not in blob
        assert REAL_SECRET not in blob
        assert b"confirmation" not in blob
        assert b"receipt" not in blob
    bundle = load_historical_evaluation_pairing(
        archive_root=archive_root,
        authority_fingerprint=authority.authority_fingerprint,
    )
    assert bundle.pairing_authority == authority
    assert set(bundle.pairing_authority.to_dict()) == {
        "schema_version",
        "actor_id",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "authority_fingerprint",
    }


def test_pairing_authority_schema_gains_no_confirmation_field(
    real_authority: HistoricalEvaluationPairingAuthority,
):
    assert (
        real_authority.schema_version
        == HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION
        == "admissible_historical_evaluation_pairing_authority_v1"
    )
    document = real_authority.to_dict()
    assert set(document) == {
        "schema_version",
        "actor_id",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "authority_fingerprint",
    }
    assert set(HistoricalEvaluationPairingAuthority.__dataclass_fields__) == set(
        document
    )
    for forbidden in (
        "confirmation_tag",
        "confirmation_tag_sha256",
        "confirmed_at",
        "confirmation_method",
        "confirmation_context",
        "secret_verifier",
    ):
        assert forbidden not in document


def test_runtime_owner_digest_authorization_behaviour_is_unchanged(
    historical_pairing,
    monkeypatch: pytest.MonkeyPatch,
):
    from admissible.delegated_gate import native_canary

    _profile, payload, authority = historical_pairing
    monkeypatch.setattr(
        NativeCanaryAuthorizationPayloadV4,
        "validated_for_authorization",
        lambda self, *, active_source_repository: self,
    )
    phrase = "owner-authorization-phrase"
    expected = hashlib.sha256(
        phrase.encode("utf-8") + b"\0" + canonical_bytes(payload.to_dict())
    ).hexdigest()
    monkeypatch.setenv(OWNER_AUTHORIZATION_DIGEST_ENV, expected)
    assert (
        native_canary._authorized(
            phrase, payload, active_source_repository="unused-by-this-pin"
        )
        is True
    )
    # A historical-pairing confirmation tag is not runtime owner authorization.
    monkeypatch.setenv(
        OWNER_AUTHORIZATION_DIGEST_ENV,
        compute_historical_pairing_confirmation_tag(
            secret=REAL_SECRET, pairing_authority=authority
        ),
    )
    assert (
        native_canary._authorized(
            phrase, payload, active_source_repository="unused-by-this-pin"
        )
        is False
    )


def test_v5_evaluation_profile_remains_non_launchable_after_confirmation(
    historical_pairing,
):
    profile, _payload, authority = historical_pairing
    assert profile.is_launchable_runtime_profile is False
    compute_historical_pairing_confirmation_tag(
        secret=REAL_SECRET, pairing_authority=authority
    )
    assert profile.is_launchable_runtime_profile is False
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert project_v5_runtime_authority_to_v2(profile).is_launchable_runtime_profile
