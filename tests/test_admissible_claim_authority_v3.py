from __future__ import annotations

import json

import pytest

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.mission_profile import (
    FLAGSHIP_INCIDENT_REPLAY_PROFILE,
    WORKFLOW_RECOVERY_PROFILE,
    ClaimAuthority,
    ClaimAuthorship,
    ClaimObligationLevel,
    ClaimSetCoverageStatus,
    GitEndStatePolicy,
    MISSION_PROFILE_SCHEMA_VERSION_V3,
    NativeMissionProfile,
    ResultClaim,
    RuntimePromptAuthority,
    VerificationAuthority,
    VerificationMode,
    WorkspaceSourceAuthority,
    WorkspaceSourceKind,
    create_native_mission_profile,
)
from admissible.delegated_gate.models import EvidenceKind


def _claim(
    claim_id: str = "claim.one",
    statement: str = "The required material exists.",
    *,
    level: ClaimObligationLevel = ClaimObligationLevel.MANDATORY,
    depends_on: tuple[str, ...] = (),
    non_claims: tuple[str, ...] = ("This does not assert runtime verification.",),
) -> ResultClaim:
    return ResultClaim(claim_id, statement, level, depends_on, non_claims)


def _authority(
    *,
    authorship: ClaimAuthorship = ClaimAuthorship.OWNER_AUTHORED,
    claims: tuple[ResultClaim, ...] | None = None,
) -> ClaimAuthority:
    return ClaimAuthority(
        authorship=authorship,
        coverage_status=ClaimSetCoverageStatus.NOT_ASSESSED,
        claims=claims or (_claim(),),
    )


def _profile(authority: ClaimAuthority | None = None) -> NativeMissionProfile:
    return create_native_mission_profile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V3,
        profile_id="claim-model-v3",
        run_id="claim-model-run",
        session_id="claim-model-run",
        gate_id="claim-model-gate",
        mission_id="claim-model-mission",
        mission_text="Create the bounded material and stop.",
        gate_objective="Exercise only the inert canonical V3 data model.",
        gate_clauses=(("claim-model.material", "The material is present."),),
        required_evidence_kinds=(EvidenceKind.TARGET_TREE.value, EvidenceKind.GIT_STATE.value),
        checkpoint_commands=(),
        completion_conditions_text="Finish the material and Git policy, then stop.",
        budgets=(1, 1, 0, 0, 0),
        timeout_seconds=60,
        stdout_byte_limit=8192,
        stderr_byte_limit=8192,
        model="auto",
        workspace_source=WorkspaceSourceAuthority(
            kind=WorkspaceSourceKind.REGISTERED_FIXTURE,
            fixture_id="claim-model-fixture",
            fixture_version=1,
        ),
        git_end_state_policy=GitEndStatePolicy(
            required_commits_added=1,
            required_complete_commit_message="feat: create bounded material",
            final_worktree_clean=True,
            final_index_clean=True,
            final_remotes_absent=True,
            required_material_paths=("README.md",),
        ),
        verification=VerificationAuthority(
            mode=VerificationMode.OBSERVED_ONLY,
            verifier_source=None,
            verifier_source_sha256=None,
            verifier_timeout_seconds=None,
            verifier_output_limit_bytes=None,
            disclose_complete_source=False,
        ),
        runtime_prompt=RuntimePromptAuthority(
            permitted_effects=("Edit and commit only in the assigned workspace.",),
            forbidden_effects=("Do not use network or invoke a provider.",),
            stop_clause="Stop after the exact one-commit policy is satisfied.",
        ),
        claim_authority=authority or _authority(),
    )


def _refingerprint(data: dict) -> dict:
    changed = json.loads(json.dumps(data))
    changed["profile_fingerprint"] = fingerprint(
        {key: value for key, value in changed.items() if key != "profile_fingerprint"}
    )
    return changed


def test_result_claim_valid_round_trip_and_order_preservation():
    claim = _claim(depends_on=("claim.two", "claim.three"), non_claims=("First", "Second"))
    loaded = ResultClaim.from_dict(claim.to_dict())
    assert loaded == claim.validated()
    assert loaded.depends_on == ("claim.two", "claim.three")
    assert loaded.non_claims == ("First", "Second")


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(extra=True),
    lambda data: data.pop("statement"),
])
def test_result_claim_requires_exact_keys(mutation):
    data = _claim().to_dict()
    mutation(data)
    with pytest.raises(ValueError, match="keys"):
        ResultClaim.from_dict(data)


@pytest.mark.parametrize("claim_id", ["", "unsafe id", "../claim"])
def test_result_claim_rejects_invalid_identifier(claim_id):
    with pytest.raises(ValueError, match="identifier"):
        _claim(claim_id=claim_id).validated()


@pytest.mark.parametrize("statement", ["", " ", "x" * 4097])
def test_result_claim_rejects_empty_or_oversized_statement(statement):
    with pytest.raises(ValueError):
        _claim(statement=statement).validated()


def test_result_claim_rejects_duplicate_and_self_dependencies():
    with pytest.raises(ValueError, match="unique"):
        _claim(depends_on=("claim.two", "claim.two")).validated()
    with pytest.raises(ValueError, match="itself"):
        _claim(depends_on=("claim.one",)).validated()


def test_result_claim_rejects_duplicate_non_claims():
    with pytest.raises(ValueError, match="unique"):
        _claim(non_claims=("Same", "Same")).validated()


@pytest.mark.parametrize("authorship", list(ClaimAuthorship))
def test_claim_authority_accepts_both_authorships_and_round_trips(authorship):
    authority = _authority(
        authorship=authorship,
        claims=(_claim("claim.two", depends_on=("claim.one",)), _claim("claim.one")),
    )
    loaded = ClaimAuthority.from_dict(authority.to_dict())
    assert loaded == authority.validated()
    assert tuple(claim.claim_id for claim in loaded.claims) == ("claim.two", "claim.one")
    assert loaded.claims[0].depends_on == ("claim.one",)


def test_claim_authority_rejects_unsupported_enums():
    data = _authority().to_dict()
    data["authorship"] = "MODEL_GENERATED"
    with pytest.raises(ValueError, match="authorship"):
        ClaimAuthority.from_dict(data)
    data = _authority().to_dict()
    data["coverage_status"] = "COMPLETE"
    with pytest.raises(ValueError, match="NOT_ASSESSED"):
        ClaimAuthority.from_dict(data)


def test_claim_authority_rejects_duplicate_and_missing_ids():
    with pytest.raises(ValueError, match="unique"):
        _authority(claims=(_claim(), _claim())).validated()
    with pytest.raises(ValueError, match="missing"):
        _authority(claims=(_claim(depends_on=("absent",)),)).validated()


def test_claim_authority_rejects_direct_and_indirect_cycles():
    direct = (_claim("a", depends_on=("b",)), _claim("b", depends_on=("a",)))
    with pytest.raises(ValueError, match="acyclic"):
        _authority(claims=direct).validated()
    indirect = (
        _claim("a", depends_on=("b",)),
        _claim("b", depends_on=("c",)),
        _claim("c", depends_on=("a",)),
    )
    with pytest.raises(ValueError, match="acyclic"):
        _authority(claims=indirect).validated()


def test_claim_authority_accepts_ordered_dependency_dag():
    claims = (
        _claim("release", depends_on=("tests", "material")),
        _claim("material"),
        _claim("tests", depends_on=("material",)),
    )
    assert _authority(claims=claims).validated().claims == claims


def test_v3_construction_round_trip_and_fingerprint_participation():
    profile = _profile()
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3
    assert profile.to_dict()["claim_authority"] == profile.claim_authority.to_dict()
    assert profile.profile_fingerprint == fingerprint(profile._body())
    assert NativeMissionProfile.from_dict(profile.to_dict()) == profile
    assert canonical_bytes(NativeMissionProfile.from_dict(profile.to_dict()).to_dict()) == canonical_bytes(profile.to_dict())


@pytest.mark.parametrize("authority", [
    _authority(claims=(_claim(statement="Changed text"),)),
    _authority(claims=(_claim("second"), _claim("claim.one"))),
    _authority(authorship=ClaimAuthorship.TEMPLATE_AUTHORED),
    _authority(claims=(_claim(non_claims=("Changed exclusion",)),)),
])
def test_v3_claim_changes_change_profile_fingerprint(authority):
    assert _profile(authority).profile_fingerprint != _profile().profile_fingerprint


def test_v3_rejects_missing_malformed_and_unknown_claim_authority():
    valid = _profile().to_dict()
    for mutation in (
        lambda data: data.pop("claim_authority"),
        lambda data: data["claim_authority"].update(extra=True),
        lambda data: data.update(extra=True),
        lambda data: data["claim_authority"]["claims"][0].update(extra=True),
    ):
        data = json.loads(json.dumps(valid))
        mutation(data)
        data = _refingerprint(data)
        with pytest.raises(ValueError):
            NativeMissionProfile.from_dict(data)


def test_v1_v2_reject_injected_claim_authority_and_v1_golden_identities_remain_exact():
    expected = {
        FLAGSHIP_INCIDENT_REPLAY_PROFILE: "ceac9c5dc344d7f5b5d24c530cd28a29012c3dcbb0f4fa7906884caec6845bc3",
        WORKFLOW_RECOVERY_PROFILE: "ed67459c803bf439ee3325cdf9fa069d48677408412ff283ab86a4234d9ae2f8",
    }
    for profile, digest in expected.items():
        before = profile.to_dict()
        assert profile.profile_fingerprint == digest
        assert canonical_bytes(before) == canonical_bytes(profile.to_dict())
        assert NativeMissionProfile.from_dict(before) == profile
        injected = {**before, "claim_authority": _authority().to_dict()}
        with pytest.raises(ValueError, match="keys"):
            NativeMissionProfile.from_dict(injected)

    v2 = _profile().to_dict()
    v2["schema_version"] = "admissible_native_mission_profile_v2"
    v2.pop("claim_authority")
    v2 = _refingerprint(v2)
    loaded = NativeMissionProfile.from_dict(v2)
    before = loaded.to_dict()
    assert NativeMissionProfile.from_dict(before) == loaded
    assert canonical_bytes(loaded.to_dict()) == canonical_bytes(before)
    with pytest.raises(ValueError, match="keys"):
        NativeMissionProfile.from_dict({**before, "claim_authority": _authority().to_dict()})
