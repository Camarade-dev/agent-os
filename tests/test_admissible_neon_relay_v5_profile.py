"""neon-relay-v5 identity, and proof that only two things changed.

An independent liveness audit established -- before any launch, so v4's single
native attempt was never spent -- that the V4 ACP authority boundary refuses the
mission's own required effects: it rejects every ``kind=edit`` tool call, so
none of the 14 material files can be created; it rejects ``npm test``; and
``git add`` and ``git commit`` are outside both the host allowlist and V4's
read-only Git grammar.  A run under v4 could only have burned its one attempt on
a mission that was not performable.

v5 therefore changes exactly two things and nothing else:

* the run identity, since v4's is retired with its preparation as historical,
  provider-free evidence;
* the mission-scoped effect authority, which is *added* -- v4 carried none,
  because none existed.

Everything the mission is made of -- text, completion conditions, frozen
verifier and its SHA-256, fixture, required paths, checkpoint, exact commit
message, model, budgets, timeout, runtime prompt and human-review non-claims --
is byte-identical to v4 and therefore to v3, v2 and v1.
"""

from __future__ import annotations

import hashlib

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_effect_authority import (
    MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION,
    NEON_RELAY_MISSION_EFFECT_AUTHORITY,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    NEON_RELAY_PROFILE,
    NEON_RELAY_V2_PROFILE,
    NEON_RELAY_V3_PROFILE,
    NEON_RELAY_V4_PROFILE,
    NEON_RELAY_V5_PROFILE,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import registered_profiles
from admissible.delegated_gate.native_executor import PROMPT_TRANSPORT_ACP_STDIO

V1 = NEON_RELAY_PROFILE
V2 = NEON_RELAY_V2_PROFILE
V3 = NEON_RELAY_V3_PROFILE
V4 = NEON_RELAY_V4_PROFILE
V5 = NEON_RELAY_V5_PROFILE

EXPECTED_V1_FINGERPRINT = "8ef57625f3fb369ff87d2981ff15753fcd45f0328c74bcb05ed81c8a61c9999d"
EXPECTED_V2_FINGERPRINT = "3dd4ce6198e450b420afab4ed1e19acfcb7e807e292d87cafdc475ad0ca2c3b6"
EXPECTED_V3_FINGERPRINT = "d871015d5a0ca8fc1ed050264a5c30845162cce8396fae6fa5fa2f0352253ec6"
EXPECTED_V4_FINGERPRINT = "6380e810995b6cd97db408fe4f434328890dafd48d0f5a7468eca010fa8fc97a"
EXPECTED_V4_DOCUMENT_SHA256 = "e6546f54856b16be28add84a19c010982f09adf946b0d251d75b39559aa9868a"

EXPECTED_V5_FINGERPRINT = "676adb0760e992745952aaf8aa829c99baab792cd3ba171a3070e8394fd125c8"
EXPECTED_V5_DOCUMENT_SHA256 = "2fecaf4e4be443d767c360bd2a6c80eb44fe4a8ea728c622ca2a650f6b8bccf3"
EXPECTED_EFFECT_AUTHORITY_FINGERPRINT = (
    "99986849ee621a825e52f1ecb362b920f1011b5665c7500d724159f482144e99"
)
EXPECTED_VERIFIER_SHA256 = "0e2afbd206933ad621b22e80755725d6436ea1f65319c914738254b0cfe001c5"


def document_sha256(profile: NativeMissionProfile) -> str:
    return hashlib.sha256(canonical_bytes(profile.to_dict())).hexdigest()


# ---------------------------------------------------------------------------
# v1 through v4 stay historically byte-identical
# ---------------------------------------------------------------------------


def test_the_four_historical_identities_are_untouched():
    """Adding an optional field must not disturb one persisted fingerprint."""

    assert V1.profile_fingerprint == EXPECTED_V1_FINGERPRINT
    assert V2.profile_fingerprint == EXPECTED_V2_FINGERPRINT
    assert V3.profile_fingerprint == EXPECTED_V3_FINGERPRINT
    assert V4.profile_fingerprint == EXPECTED_V4_FINGERPRINT
    assert document_sha256(V4) == EXPECTED_V4_DOCUMENT_SHA256
    # Omit-when-absent: a profile carrying no effect authority produces the
    # exact canonical bytes it produced before the field existed.
    for profile in (V1, V2, V3, V4):
        assert profile.mission_effect_authority is None
        assert "mission_effect_authority" not in profile.to_dict()


def test_all_five_identities_are_registered_and_distinct():
    profiles = registered_profiles()
    assert profiles["neon-relay-v4"].profile_fingerprint == EXPECTED_V4_FINGERPRINT
    assert profiles["neon-relay-v5"].profile_fingerprint == EXPECTED_V5_FINGERPRINT
    every = (V1, V2, V3, V4, V5)
    assert len({p.profile_fingerprint for p in every}) == 5
    assert len({p.run_id for p in every}) == 5
    assert len({p.session_id for p in every}) == 5


# ---------------------------------------------------------------------------
# v5 identity
# ---------------------------------------------------------------------------


def test_neon_relay_v5_identity_is_exact():
    assert V5.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2
    assert V5.profile_id == "neon-relay-v5"
    assert V5.mission_id == "native-neon-relay"
    assert V5.gate_id == "neon-relay-gate"
    assert V5.run_id == "native-cursor-neon-relay-005"
    assert V5.session_id == "native-cursor-neon-relay-005"
    assert V5.profile_fingerprint == EXPECTED_V5_FINGERPRINT
    assert document_sha256(V5) == EXPECTED_V5_DOCUMENT_SHA256
    assert V5.is_launchable_runtime_profile


def test_neon_relay_v5_keeps_the_acp_stdio_transport():
    assert V5.prompt_transport == PROMPT_TRANSPORT_ACP_STDIO
    assert V5.to_dict()["prompt_transport"] == PROMPT_TRANSPORT_ACP_STDIO


def test_exactly_the_identity_and_the_effect_authority_differ_between_v4_and_v5():
    a, b = V4.to_dict(), V5.to_dict()
    differing = {
        key for key in set(a) | set(b) if a.get(key, "<absent>") != b.get(key, "<absent>")
    }
    assert differing == {
        "profile_id", "run_id", "session_id", "profile_fingerprint",
        "mission_effect_authority",
    }


# ---------------------------------------------------------------------------
# The mission-scoped effect authority is in the profile and its fingerprint
# ---------------------------------------------------------------------------


def test_the_effect_authority_is_carried_and_fingerprinted(  ):
    authority = V5.mission_effect_authority
    assert authority is not None
    assert authority == NEON_RELAY_MISSION_EFFECT_AUTHORITY
    assert authority.schema_version == MISSION_EFFECT_AUTHORITY_SCHEMA_VERSION
    assert authority.authority_fingerprint == EXPECTED_EFFECT_AUTHORITY_FINGERPRINT
    # It is inside the canonical body, so it is inside the profile fingerprint.
    assert V5._body()["mission_effect_authority"]["authority_fingerprint"] == (
        EXPECTED_EFFECT_AUTHORITY_FINGERPRINT
    )
    assert V5.to_dict()["mission_effect_authority"] == authority.to_dict()


def test_the_effect_authority_cannot_contradict_the_git_end_state_policy():
    policy = V5.effective_git_end_state_policy
    authority = V5.mission_effect_authority
    assert authority.writable_material_paths == policy.required_material_paths
    assert authority.exact_commit_message == policy.required_complete_commit_message

    drifted = NEON_RELAY_MISSION_EFFECT_AUTHORITY.to_dict()
    drifted["writable_material_paths"] = list(drifted["writable_material_paths"])[:-1]
    document = V5.to_dict()
    document["mission_effect_authority"] = drifted
    with pytest.raises(Exception):
        NativeMissionProfile.from_dict(document)


def test_the_authority_names_exactly_the_mission_effects():
    authority = V5.mission_effect_authority
    assert len(authority.writable_material_paths) == 14
    assert authority.creatable_directories == ("src", "test")
    assert authority.exact_commit_message == "feat: build playable Neon Relay browser game"
    assert authority.local_verification_commands == (
        ("npm", "run", "test"), ("npm", "test"),
        ("npm.cmd", "run", "test"), ("npm.cmd", "test"),
    )
    assert authority.approval_bounds["mission_git_commit"] == 1
    assert "delete" not in authority.allowed_edit_operations
    assert set(authority.constraints) >= {
        "no_git_remote_may_exist_or_be_created",
        "no_push_or_fetch_is_authorized",
        "no_deployment_publication_or_server_is_authorized",
        "only_allow_once_may_ever_be_selected",
    }


# ---------------------------------------------------------------------------
# Everything the mission is made of is byte-identical to v4
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
def test_v5_mission_field_is_byte_identical_to_v4_v3_v2_and_v1(field):
    assert getattr(V5, field) == getattr(V4, field)
    assert getattr(V5, field) == getattr(V3, field)
    assert getattr(V5, field) == getattr(V2, field)
    if field != "prompt_transport":
        assert getattr(V5, field) == getattr(V1, field)


def test_v5_verifier_source_is_unchanged_and_still_disclosed():
    assert V5.verifier_source == V1.verifier_source
    assert hashlib.sha256(V5.verifier_source.encode("utf-8")).hexdigest() == (
        EXPECTED_VERIFIER_SHA256
    )
    assert V5.verifier_source_sha256 == EXPECTED_VERIFIER_SHA256
    assert V5.verification.disclose_complete_source is True


def test_v5_keeps_the_one_shot_no_retry_no_repair_budgets():
    provider, attempts, repairs, auditors, retries = V5.budgets
    assert (provider, attempts, repairs, auditors, retries) == tuple(V1.budgets)
    assert provider == 1 and attempts == 1 and repairs == 0 and retries == 0 and auditors == 0


def test_v5_keeps_the_mission_timeout_and_checkpoint():
    assert V5.timeout_seconds == 2700
    assert [(c.command_id, tuple(c.argv)) for c in V5.checkpoint_commands] == [
        ("npm-test", ("npm.cmd", "test")),
    ]


def test_v5_keeps_the_no_remote_no_push_git_end_state():
    policy = V5.effective_git_end_state_policy
    assert policy.required_commits_added == 1
    assert policy.final_worktree_clean is True
    assert policy.final_index_clean is True
    assert policy.final_remotes_absent is True


def test_v5_round_trips_with_a_stable_fingerprint():
    reloaded = NativeMissionProfile.from_dict(V5.to_dict())
    assert reloaded.profile_fingerprint == EXPECTED_V5_FINGERPRINT
    assert document_sha256(reloaded) == EXPECTED_V5_DOCUMENT_SHA256
    assert reloaded.mission_effect_authority == NEON_RELAY_MISSION_EFFECT_AUTHORITY
    assert reloaded == V5


def test_a_null_effect_authority_key_is_not_a_second_canonical_document():
    document = V4.to_dict()
    document["mission_effect_authority"] = None
    with pytest.raises(ValueError):
        NativeMissionProfile.from_dict(document)
