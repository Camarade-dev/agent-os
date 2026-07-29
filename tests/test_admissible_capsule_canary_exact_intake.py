"""Optional exact-material policy for canonical intake.

The exact policy is a closed, immutable extension of `IntakeAuthority`: for an
exact-authorized file it fixes the normalized relative path, the regular-file
mode, the byte size and the SHA-256.  Wrong bytes, wrong size or wrong mode
must make intake itself reject, before `ACCEPTED_INTAKE_PUBLISHED`; they must
not be deferred to checkpoint or behavioral verification.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from admissible.capsule.intake import (
    CANARY_EXACT_AUTHORITY,
    CANARY_TXT_BYTES,
    CANARY_TXT_GIT_MODE,
    CANARY_TXT_RELATIVE_PATH,
    NEON_RELAY_AUTHORITY,
    AcceptedMaterialIdentity,
    CanonicalIntake,
    ExactMaterialRecord,
    IntakeAuthority,
    IntakePublicationState,
    RejectionCode,
    validate_and_copy,
)


def _canary_source(tmp_path: Path, content: bytes, *, mode: int = 0o644) -> Path:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    target = source / CANARY_TXT_RELATIVE_PATH
    target.write_bytes(content)
    target.chmod(mode)
    return source


def _run(tmp_path: Path, source: Path, authority=CANARY_EXACT_AUTHORITY):
    return validate_and_copy(
        source,
        authority,
        tmp_path / "accepted",
        tmp_path / "intake-evidence.json",
    )


# --- schema ------------------------------------------------------------


def test_canary_fixture_size_and_digest_are_derived_not_hand_entered():
    record = CANARY_EXACT_AUTHORITY.exact_material_by_path[CANARY_TXT_RELATIVE_PATH]
    assert CANARY_TXT_BYTES == b"admissible-chatgpt-codex-canary-v1\n"
    assert record.relative_path == "CANARY.txt"
    assert record.git_mode == "100644"
    assert record.size == len(CANARY_TXT_BYTES)
    assert record.sha256 == hashlib.sha256(CANARY_TXT_BYTES).hexdigest()
    assert record.to_dict() == {
        "relative_path": "CANARY.txt",
        "git_mode": "100644",
        "size": len(CANARY_TXT_BYTES),
        "sha256": hashlib.sha256(CANARY_TXT_BYTES).hexdigest(),
    }


def test_exact_policy_is_inside_the_intake_authority_fingerprint():
    without = IntakeAuthority.create(
        authority_id="chatgpt_codex_canary_v1",
        authority_paths=(CANARY_TXT_RELATIVE_PATH,),
        allowed_directories=(),
    )
    assert without.authority_fingerprint != CANARY_EXACT_AUTHORITY.authority_fingerprint
    other = IntakeAuthority.create(
        authority_id="chatgpt_codex_canary_v1",
        authority_paths=(CANARY_TXT_RELATIVE_PATH,),
        allowed_directories=(),
        exact_material=(
            ExactMaterialRecord.for_bytes(CANARY_TXT_RELATIVE_PATH, b"different\n"),
        ),
    )
    assert other.authority_fingerprint != CANARY_EXACT_AUTHORITY.authority_fingerprint


def test_exact_policy_round_trips_through_durable_evidence():
    restored = IntakeAuthority.from_dict(json.loads(json.dumps(
        CANARY_EXACT_AUTHORITY.to_dict()
    )))
    assert restored == CANARY_EXACT_AUTHORITY
    assert restored.authority_fingerprint == CANARY_EXACT_AUTHORITY.authority_fingerprint
    assert restored.exact_material == CANARY_EXACT_AUTHORITY.exact_material


def test_exact_policy_is_immutable_and_closed():
    record = CANARY_EXACT_AUTHORITY.exact_material[0]
    with pytest.raises(Exception):
        record.size = 1  # frozen dataclass
    with pytest.raises(ValueError, match="outside the intake authority"):
        IntakeAuthority.create(
            authority_id="mismatched",
            authority_paths=("kept.txt",),
            allowed_directories=(),
            exact_material=(
                ExactMaterialRecord.for_bytes("other.txt", b"x"),
            ),
        )
    with pytest.raises(ValueError, match="normalized relative path"):
        ExactMaterialRecord.for_bytes("../escape.txt", b"x")
    with pytest.raises(ValueError, match="mode"):
        ExactMaterialRecord.for_bytes("CANARY.txt", b"x", git_mode="120000")


def test_non_exact_authorities_keep_their_previous_identity():
    """Missions that authorize paths and bounds without fixed bytes are intact."""

    assert NEON_RELAY_AUTHORITY.exact_material == ()
    assert "exact_material" not in NEON_RELAY_AUTHORITY.to_dict()
    legacy = dict(NEON_RELAY_AUTHORITY.to_dict())
    assert IntakeAuthority.from_dict(legacy) == NEON_RELAY_AUTHORITY


# --- acceptance --------------------------------------------------------


def test_exact_intake_accepts_the_canary_file(tmp_path: Path):
    evidence = _run(tmp_path, _canary_source(tmp_path, CANARY_TXT_BYTES))
    assert evidence.ruling == "ACCEPTED"
    assert evidence.publication_state is IntakePublicationState.ACCEPTED_INTAKE_PUBLISHED
    assert (tmp_path / "accepted" / "CANARY.txt").read_bytes() == CANARY_TXT_BYTES
    record = evidence.files[0]
    assert record.size == len(CANARY_TXT_BYTES)
    assert record.git_mode == CANARY_TXT_GIT_MODE
    identity = AcceptedMaterialIdentity.from_intake_evidence(evidence)
    assert identity.authorized_relative_paths == ("CANARY.txt",)
    assert identity.files[0].sha256 == hashlib.sha256(CANARY_TXT_BYTES).hexdigest()


def test_non_exact_authority_still_accepts_arbitrary_authorized_bytes(tmp_path: Path):
    authority = IntakeAuthority.create(
        authority_id="bounds_only_v1",
        authority_paths=(CANARY_TXT_RELATIVE_PATH,),
        allowed_directories=(),
    )
    evidence = _run(
        tmp_path,
        _canary_source(tmp_path, b"anything within bounds\n"),
        authority=authority,
    )
    assert evidence.ruling == "ACCEPTED"


# --- exact refusals ----------------------------------------------------


def _codes(evidence):
    return {reason.code for reason in evidence.rejection_reasons}


def test_exact_intake_refuses_a_single_wrong_byte(tmp_path: Path):
    wrong = bytearray(CANARY_TXT_BYTES)
    wrong[0] = ord("A")
    evidence = _run(tmp_path, _canary_source(tmp_path, bytes(wrong)))
    assert evidence.ruling == "REJECTED"
    assert evidence.publication_state is IntakePublicationState.REJECTED
    assert RejectionCode.EXACT_BYTES_MISMATCH in _codes(evidence)
    assert not (tmp_path / "accepted").exists()


def test_exact_intake_refuses_a_missing_final_newline(tmp_path: Path):
    evidence = _run(
        tmp_path,
        _canary_source(tmp_path, CANARY_TXT_BYTES.rstrip(b"\n")),
    )
    assert evidence.ruling == "REJECTED"
    assert RejectionCode.EXACT_SIZE_MISMATCH in _codes(evidence)
    assert RejectionCode.EXACT_BYTES_MISMATCH in _codes(evidence)
    assert not (tmp_path / "accepted").exists()


def test_exact_intake_refuses_a_wrong_size(tmp_path: Path):
    evidence = _run(tmp_path, _canary_source(tmp_path, CANARY_TXT_BYTES + b"\n"))
    assert evidence.ruling == "REJECTED"
    assert RejectionCode.EXACT_SIZE_MISMATCH in _codes(evidence)


def test_exact_intake_refuses_a_wrong_mode(tmp_path: Path):
    evidence = _run(
        tmp_path,
        _canary_source(tmp_path, CANARY_TXT_BYTES, mode=0o755),
    )
    assert evidence.ruling == "REJECTED"
    assert RejectionCode.EXACT_MODE_MISMATCH in _codes(evidence)
    assert not (tmp_path / "accepted").exists()


def test_exact_intake_refusal_is_not_deferred_to_checkpoint_or_behavior(
    tmp_path: Path,
):
    """Intake itself rules, and nothing reaches the published state."""

    source = _canary_source(tmp_path, b"admissible-chatgpt-codex-canary-v2\n")
    with CanonicalIntake(source, CANARY_EXACT_AUTHORITY) as intake:
        intake.observe()
        assert intake.reasons  # complete observation already carries the refusal
        evidence = intake.copy_and_publish(
            tmp_path / "accepted",
            tmp_path / "intake-evidence.json",
        )
    assert evidence.ruling == "REJECTED"
    assert evidence.publication_state is IntakePublicationState.REJECTED
    assert evidence.files == ()
    with pytest.raises(ValueError, match="published accepted intake evidence"):
        AcceptedMaterialIdentity.from_intake_evidence(evidence)


def test_exact_intake_preserves_complete_observation_and_race_defenses(
    tmp_path: Path,
):
    source = _canary_source(tmp_path, CANARY_TXT_BYTES)
    (source / "extra.txt").write_bytes(b"unauthorized\n")
    evidence = _run(tmp_path, source)
    assert evidence.ruling == "REJECTED"
    assert RejectionCode.EXTRA_PATH in _codes(evidence)
    # Every reason is reported together; observation is not short-circuited.
    assert {reason.path for reason in evidence.rejection_reasons} == {"extra.txt"}

    mutating = _canary_source(tmp_path / "race", CANARY_TXT_BYTES)
    with CanonicalIntake(mutating, CANARY_EXACT_AUTHORITY) as intake:
        intake.observe()
        assert not intake.reasons
        (mutating / CANARY_TXT_RELATIVE_PATH).write_bytes(b"swapped after observe\n")
        raced = intake.copy_and_publish(
            tmp_path / "race-accepted",
            tmp_path / "race-evidence.json",
        )
    assert raced.ruling == "REJECTED"
    assert RejectionCode.SOURCE_MUTATED in _codes(raced)
    assert not (tmp_path / "race-accepted").exists()
