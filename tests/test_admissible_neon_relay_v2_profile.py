"""neon-relay-v2 identity, and proof that the transport field changed nothing else.

neon-relay-v1's argv transport is unspawnable on Windows (a 64660-character
prompt against a 32766-character command-line limit) and its single native
attempt is durably consumed by the PROCESS_SPAWN_FAILED run, so a new run
identity is mechanically required.  v2 changes exactly that identity and the
prompt transport; every mission-bearing byte is unchanged.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    NEON_RELAY_PROFILE,
    NEON_RELAY_V2_PROFILE,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import registered_profiles
from admissible.delegated_gate.native_executor import (
    PROMPT_TRANSPORT_ACP_STDIO,
    PROMPT_TRANSPORT_ARGV,
)

V1 = NEON_RELAY_PROFILE
V2 = NEON_RELAY_V2_PROFILE

EXPECTED_V1_FINGERPRINT = "8ef57625f3fb369ff87d2981ff15753fcd45f0328c74bcb05ed81c8a61c9999d"
EXPECTED_V1_DOCUMENT_SHA256 = "27f4d6e0c81937c1a3e76da7c9c067738f879bc3f5a2a874ab48274e9f227e14"
EXPECTED_VERIFIER_SHA256 = "0e2afbd206933ad621b22e80755725d6436ea1f65319c914738254b0cfe001c5"

EXPECTED_V2_FINGERPRINT = "3dd4ce6198e450b420afab4ed1e19acfcb7e807e292d87cafdc475ad0ca2c3b6"
EXPECTED_V2_DOCUMENT_SHA256 = "eae3b8e7339a2d25758079fd0c7572ceb948a7a715e05bb95525acadb66cd5e5"


def document_sha256(profile: NativeMissionProfile) -> str:
    return hashlib.sha256(canonical_bytes(profile.to_dict())).hexdigest()


# ---------------------------------------------------------------------------
# v1 is untouched
# ---------------------------------------------------------------------------


def test_neon_relay_v1_identity_is_byte_identical():
    assert V1.profile_id == "neon-relay-v1"
    assert V1.run_id == "native-cursor-neon-relay-001"
    assert V1.session_id == "native-cursor-neon-relay-001"
    assert V1.profile_fingerprint == EXPECTED_V1_FINGERPRINT
    assert document_sha256(V1) == EXPECTED_V1_DOCUMENT_SHA256
    assert V1.verifier_source_sha256 == EXPECTED_VERIFIER_SHA256


def test_neon_relay_v1_keeps_its_historical_argv_transport():
    assert V1.prompt_transport == PROMPT_TRANSPORT_ARGV
    # Omit-when-default: the canonical body carries no transport key at all, so
    # the fingerprint is exactly what it was before the field existed.
    assert "prompt_transport" not in V1._body()
    assert "prompt_transport" not in V1.to_dict()


# ---------------------------------------------------------------------------
# v2 identity
# ---------------------------------------------------------------------------


def test_neon_relay_v2_identity_is_exact():
    assert V2.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2
    assert V2.profile_id == "neon-relay-v2"
    assert V2.mission_id == "native-neon-relay"
    assert V2.gate_id == "neon-relay-gate"
    assert V2.run_id == "native-cursor-neon-relay-002"
    assert V2.session_id == "native-cursor-neon-relay-002"
    assert V2.prompt_transport == PROMPT_TRANSPORT_ACP_STDIO
    assert V2.profile_fingerprint == EXPECTED_V2_FINGERPRINT
    assert document_sha256(V2) == EXPECTED_V2_DOCUMENT_SHA256
    assert V2.is_launchable_runtime_profile


def test_neon_relay_v2_declares_the_transport_in_its_canonical_body():
    body = V2._body()
    assert body["prompt_transport"] == PROMPT_TRANSPORT_ACP_STDIO
    assert V2.to_dict()["prompt_transport"] == PROMPT_TRANSPORT_ACP_STDIO


def test_neon_relay_v2_is_registered_alongside_v1():
    profiles = registered_profiles()
    assert profiles["neon-relay-v1"].profile_fingerprint == EXPECTED_V1_FINGERPRINT
    assert profiles["neon-relay-v2"].profile_fingerprint == EXPECTED_V2_FINGERPRINT


# ---------------------------------------------------------------------------
# Everything the mission is made of is byte-identical
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "mission_text",
        "completion_conditions_text",
        "verifier_source",
        "verifier_source_sha256",
        "verifier_timeout_seconds",
        "verifier_output_limit_bytes",
        "required_material_paths",
        "required_commit_message",
        "gate_id",
        "mission_id",
        "gate_objective",
        "gate_clauses",
        "required_evidence_kinds",
        "checkpoint_commands",
        "budgets",
        "model",
        "timeout_seconds",
        "stdout_byte_limit",
        "stderr_byte_limit",
        "workspace_source",
        "git_end_state_policy",
        "verification",
        "runtime_prompt",
    ],
)
def test_v2_mission_field_is_byte_identical_to_v1(field):
    assert getattr(V2, field) == getattr(V1, field)


def test_only_identity_and_transport_differ_between_v1_and_v2():
    a, b = V1.to_dict(), V2.to_dict()
    differing = {
        key for key in set(a) | set(b) if a.get(key, "<absent>") != b.get(key, "<absent>")
    }
    assert differing == {
        "profile_id", "run_id", "session_id", "prompt_transport", "profile_fingerprint",
    }


def test_v2_verifier_source_is_unchanged_and_still_disclosed():
    assert V2.verifier_source == V1.verifier_source
    assert hashlib.sha256(V2.verifier_source.encode("utf-8")).hexdigest() == (
        EXPECTED_VERIFIER_SHA256
    )
    assert V2.verification.disclose_complete_source is True


def test_v2_keeps_the_one_shot_no_retry_no_repair_budgets():
    provider, attempts, repairs, auditors, retries = V2.budgets
    assert (provider, attempts, repairs, auditors, retries) == tuple(V1.budgets)
    assert repairs == 0 and retries == 0


# ---------------------------------------------------------------------------
# Schema compatibility
# ---------------------------------------------------------------------------


def test_every_registered_profile_round_trips_with_a_stable_fingerprint():
    for profile_id, profile in registered_profiles().items():
        reloaded = NativeMissionProfile.from_dict(profile.to_dict())
        assert reloaded.profile_fingerprint == profile.profile_fingerprint, profile_id
        assert reloaded.prompt_transport == profile.prompt_transport, profile_id


def test_argv_profiles_never_serialize_a_transport_key():
    for profile_id, profile in registered_profiles().items():
        if profile.prompt_transport == PROMPT_TRANSPORT_ARGV:
            assert "prompt_transport" not in profile.to_dict(), profile_id


def test_a_document_without_the_transport_key_defaults_to_argv():
    document = V1.to_dict()
    assert "prompt_transport" not in document
    reloaded = NativeMissionProfile.from_dict(document)
    assert reloaded.prompt_transport == PROMPT_TRANSPORT_ARGV
    assert reloaded.profile_fingerprint == EXPECTED_V1_FINGERPRINT


def test_an_unknown_transport_value_is_rejected():
    document = V2.to_dict()
    document["prompt_transport"] = "SOMETHING_ELSE"
    with pytest.raises(ValueError):
        NativeMissionProfile.from_dict(document)


def test_an_explicit_argv_transport_key_is_rejected_as_an_unexpected_field():
    """ARGV_PROMPT is always omitted, so an explicit key is not a valid document."""

    document = V1.to_dict()
    document["prompt_transport"] = PROMPT_TRANSPORT_ARGV
    with pytest.raises(ValueError):
        NativeMissionProfile.from_dict(document)


def test_a_non_launchable_schema_cannot_carry_a_non_argv_transport():
    for profile in registered_profiles().values():
        if profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION:
            document = profile.to_dict()
            document["prompt_transport"] = PROMPT_TRANSPORT_ACP_STDIO
            with pytest.raises(ValueError):
                NativeMissionProfile.from_dict(document)
            break


def test_historical_v3_v4_v5_profiles_stay_non_launchable_and_argv():
    for profile_id, profile in registered_profiles().items():
        if profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V2:
            assert profile.prompt_transport == PROMPT_TRANSPORT_ARGV, profile_id
            if profile.has_nested_runtime_authority:
                assert not profile.is_launchable_runtime_profile, profile_id
