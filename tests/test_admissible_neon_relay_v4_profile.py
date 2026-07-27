"""neon-relay-v4 identity, and proof that only the run identity changed.

The authorized ``native-cursor-neon-relay-003`` ACP run reserved its single
native attempt, spawned a real provider and then died on the *client* side of
the protocol: ``cursor/update_todos`` was unanswerable, both permission requests
had already been granted with ``allow_always`` (one of them
``cmd /c "rmdir /s /q %SystemDrive%"``), and the child environment omitted the
three Windows shell-folder variables.  v3's attempt is durably consumed and its
run identity can never be reused.

The repair lives in the ACP client and the backend attestation, not in the
mission, so v4 changes exactly the run identity: the ACP_STDIO transport, the
mission text, the completion conditions, the frozen verifier and its SHA-256,
the fixture, the required paths, the budgets, the checkpoint, the model, the
timeouts and the human-review non-claims are byte-identical to v3 and therefore
to v2 and v1.
"""

from __future__ import annotations

import hashlib

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    NEON_RELAY_PROFILE,
    NEON_RELAY_V2_PROFILE,
    NEON_RELAY_V3_PROFILE,
    NEON_RELAY_V4_PROFILE,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import registered_profiles
from admissible.delegated_gate.native_executor import PROMPT_TRANSPORT_ACP_STDIO

V1 = NEON_RELAY_PROFILE
V2 = NEON_RELAY_V2_PROFILE
V3 = NEON_RELAY_V3_PROFILE
V4 = NEON_RELAY_V4_PROFILE

EXPECTED_V1_FINGERPRINT = "8ef57625f3fb369ff87d2981ff15753fcd45f0328c74bcb05ed81c8a61c9999d"
EXPECTED_V1_DOCUMENT_SHA256 = "27f4d6e0c81937c1a3e76da7c9c067738f879bc3f5a2a874ab48274e9f227e14"
EXPECTED_V2_FINGERPRINT = "3dd4ce6198e450b420afab4ed1e19acfcb7e807e292d87cafdc475ad0ca2c3b6"
EXPECTED_V2_DOCUMENT_SHA256 = "eae3b8e7339a2d25758079fd0c7572ceb948a7a715e05bb95525acadb66cd5e5"
EXPECTED_V3_FINGERPRINT = "d871015d5a0ca8fc1ed050264a5c30845162cce8396fae6fa5fa2f0352253ec6"
EXPECTED_V3_DOCUMENT_SHA256 = "be6b69d402241ab64ff63e4a8041d5371dfc5e797929968ff557bbc8a2db8d93"

EXPECTED_V4_FINGERPRINT = "6380e810995b6cd97db408fe4f434328890dafd48d0f5a7468eca010fa8fc97a"
EXPECTED_V4_DOCUMENT_SHA256 = "e6546f54856b16be28add84a19c010982f09adf946b0d251d75b39559aa9868a"
EXPECTED_VERIFIER_SHA256 = "0e2afbd206933ad621b22e80755725d6436ea1f65319c914738254b0cfe001c5"


def document_sha256(profile: NativeMissionProfile) -> str:
    return hashlib.sha256(canonical_bytes(profile.to_dict())).hexdigest()


# ---------------------------------------------------------------------------
# v1, v2 and v3 stay historically byte-identical
# ---------------------------------------------------------------------------


def test_v1_v2_and_v3_identities_are_untouched():
    assert (V1.profile_fingerprint, document_sha256(V1)) == (
        EXPECTED_V1_FINGERPRINT, EXPECTED_V1_DOCUMENT_SHA256,
    )
    assert (V2.profile_fingerprint, document_sha256(V2)) == (
        EXPECTED_V2_FINGERPRINT, EXPECTED_V2_DOCUMENT_SHA256,
    )
    assert (V3.profile_fingerprint, document_sha256(V3)) == (
        EXPECTED_V3_FINGERPRINT, EXPECTED_V3_DOCUMENT_SHA256,
    )
    assert V1.run_id == "native-cursor-neon-relay-001"
    assert V2.run_id == "native-cursor-neon-relay-002"
    assert V3.run_id == "native-cursor-neon-relay-003"


def test_all_four_identities_are_registered_and_distinct():
    profiles = registered_profiles()
    assert profiles["neon-relay-v1"].profile_fingerprint == EXPECTED_V1_FINGERPRINT
    assert profiles["neon-relay-v2"].profile_fingerprint == EXPECTED_V2_FINGERPRINT
    assert profiles["neon-relay-v3"].profile_fingerprint == EXPECTED_V3_FINGERPRINT
    assert profiles["neon-relay-v4"].profile_fingerprint == EXPECTED_V4_FINGERPRINT
    assert len({p.profile_fingerprint for p in (V1, V2, V3, V4)}) == 4
    assert len({p.run_id for p in (V1, V2, V3, V4)}) == 4
    assert len({p.session_id for p in (V1, V2, V3, V4)}) == 4


# ---------------------------------------------------------------------------
# v4 identity
# ---------------------------------------------------------------------------


def test_neon_relay_v4_identity_is_exact():
    assert V4.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2
    assert V4.profile_id == "neon-relay-v4"
    assert V4.mission_id == "native-neon-relay"
    assert V4.gate_id == "neon-relay-gate"
    assert V4.run_id == "native-cursor-neon-relay-004"
    assert V4.session_id == "native-cursor-neon-relay-004"
    assert V4.profile_fingerprint == EXPECTED_V4_FINGERPRINT
    assert document_sha256(V4) == EXPECTED_V4_DOCUMENT_SHA256
    assert V4.is_launchable_runtime_profile


def test_neon_relay_v4_keeps_the_acp_stdio_transport():
    assert V4.prompt_transport == PROMPT_TRANSPORT_ACP_STDIO
    assert V4._body()["prompt_transport"] == PROMPT_TRANSPORT_ACP_STDIO
    assert V4.to_dict()["prompt_transport"] == PROMPT_TRANSPORT_ACP_STDIO


def test_only_the_run_identity_differs_between_v3_and_v4():
    """The ACP authority repair changed no mission-bearing profile field."""

    a, b = V3.to_dict(), V4.to_dict()
    differing = {key for key in set(a) | set(b) if a.get(key, "<absent>") != b.get(key, "<absent>")}
    assert differing == {"profile_id", "run_id", "session_id", "profile_fingerprint"}


# ---------------------------------------------------------------------------
# Everything the mission is made of is byte-identical to v3
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
        "prompt_transport",
    ],
)
def test_v4_mission_field_is_byte_identical_to_v3_v2_and_v1(field):
    assert getattr(V4, field) == getattr(V3, field)
    assert getattr(V4, field) == getattr(V2, field)
    if field != "prompt_transport":
        assert getattr(V4, field) == getattr(V1, field)


def test_v4_verifier_source_is_unchanged_and_still_disclosed():
    assert V4.verifier_source == V1.verifier_source
    assert hashlib.sha256(V4.verifier_source.encode("utf-8")).hexdigest() == EXPECTED_VERIFIER_SHA256
    assert V4.verifier_source_sha256 == EXPECTED_VERIFIER_SHA256
    assert V4.verification.disclose_complete_source is True


def test_v4_keeps_the_one_shot_no_retry_no_repair_budgets():
    provider, attempts, repairs, auditors, retries = V4.budgets
    assert (provider, attempts, repairs, auditors, retries) == tuple(V1.budgets)
    assert provider == 1 and attempts == 1 and repairs == 0 and retries == 0 and auditors == 0


def test_v4_keeps_the_mission_timeout_and_checkpoint():
    assert V4.timeout_seconds == 2700
    assert [(c.command_id, tuple(c.argv)) for c in V4.checkpoint_commands] == [
        ("npm-test", ("npm.cmd", "test")),
    ]


def test_v4_round_trips_with_a_stable_fingerprint():
    reloaded = NativeMissionProfile.from_dict(V4.to_dict())
    assert reloaded.profile_fingerprint == EXPECTED_V4_FINGERPRINT
    assert reloaded.prompt_transport == PROMPT_TRANSPORT_ACP_STDIO
    assert document_sha256(reloaded) == EXPECTED_V4_DOCUMENT_SHA256
