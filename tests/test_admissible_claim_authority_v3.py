from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from dataclasses import replace
from unittest import mock

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
    MAX_CLAIMS_PER_AUTHORITY,
    MAX_DEPENDENCIES_PER_CLAIM,
    MAX_NON_CLAIMS_PER_CLAIM,
    NativeMissionProfile,
    ResultClaim,
    RuntimePromptAuthority,
    VerificationAuthority,
    VerificationMode,
    WorkspaceSourceAuthority,
    WorkspaceSourceKind,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.models import EvidenceKind
from admissible.delegated_gate.native_canary import (
    NativeCanaryCoordinator,
    NativeCanaryStatus,
    build_native_agent_prompt,
    create_canary_session,
    observe_initialized_workspace_identity,
    run_native_mission_application,
)
from admissible.delegated_gate.state import Phase


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


def test_claim_authority_collection_bounds_are_inclusive():
    claims = tuple(_claim(f"claim.{index}") for index in range(MAX_CLAIMS_PER_AUTHORITY))
    assert len(_authority(claims=claims).validated().claims) == MAX_CLAIMS_PER_AUTHORITY
    with pytest.raises(ValueError, match="claims cannot exceed"):
        _authority(claims=claims + (_claim("claim.overflow"),)).validated()

    dependencies = tuple(f"dependency.{index}" for index in range(MAX_DEPENDENCIES_PER_CLAIM))
    dependency_claims = (_claim("root", depends_on=dependencies),) + tuple(
        _claim(dependency) for dependency in dependencies
    )
    assert len(_authority(claims=dependency_claims).validated().claims[0].depends_on) == 64
    with pytest.raises(ValueError, match="dependencies cannot exceed"):
        _claim(depends_on=dependencies + ("dependency.overflow",)).validated()

    non_claims = tuple(f"Excluded assertion {index}" for index in range(MAX_NON_CLAIMS_PER_CLAIM))
    assert len(_claim(non_claims=non_claims).validated().non_claims) == 64
    with pytest.raises(ValueError, match="non-claims cannot exceed"):
        _claim(non_claims=non_claims + ("Excluded overflow",)).validated()


def test_claim_authority_iterative_graph_validation_covers_deep_and_disconnected_graphs():
    chain = tuple(
        _claim(f"chain.{index}", depends_on=((f"chain.{index + 1}",) if index + 1 < 256 else ()))
        for index in range(256)
    )
    assert _authority(claims=chain).validated().claims == chain

    long_cycle = tuple(
        _claim(f"cycle.{index}", depends_on=(f"cycle.{(index + 1) % 256}",))
        for index in range(256)
    )
    with pytest.raises(ValueError, match="acyclic"):
        _authority(claims=long_cycle).validated()

    disconnected_cycle = (
        _claim("dag.root", depends_on=("dag.leaf",)), _claim("dag.leaf"),
        _claim("cycle.a", depends_on=("cycle.b",)), _claim("cycle.b", depends_on=("cycle.a",)),
    )
    with pytest.raises(ValueError, match="acyclic"):
        _authority(claims=disconnected_cycle).validated()

    disconnected_dag = (
        _claim("left.root", depends_on=("left.leaf",)), _claim("left.leaf"),
        _claim("right.root", depends_on=("right.leaf",)), _claim("right.leaf"),
    )
    assert _authority(claims=disconnected_dag).validated().claims == disconnected_dag
    diamond = (
        _claim("top", depends_on=("left", "right")),
        _claim("left", depends_on=("bottom",)),
        _claim("right", depends_on=("bottom",)), _claim("bottom"),
    )
    assert _authority(claims=diamond).validated().claims == diamond


def test_claim_authority_deep_chain_validation_is_non_recursive_in_child_process():
    script = """
import sys
from admissible.delegated_gate.mission_profile import (
    ClaimAuthority, ClaimAuthorship, ClaimObligationLevel,
    ClaimSetCoverageStatus, ResultClaim,
)
sys.setrecursionlimit(80)
claims = tuple(
    ResultClaim(
        f"chain.{index}", "Bounded claim.", ClaimObligationLevel.MANDATORY,
        ((f"chain.{index + 1}",) if index + 1 < 256 else ()), (),
    )
    for index in range(256)
)
ClaimAuthority(
    ClaimAuthorship.OWNER_AUTHORED,
    ClaimSetCoverageStatus.NOT_ASSESSED,
    claims,
).validated()
"""
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("field", ["depends_on", "non_claims"])
@pytest.mark.parametrize("invalid", [True, 1])
def test_result_claim_rejects_boolean_and_non_string_collection_values(field, invalid):
    values = {"depends_on": (), "non_claims": ()}
    values[field] = (invalid,)
    with pytest.raises(ValueError):
        _claim(**values).validated()


def test_direct_invalid_coverage_status_and_unknown_nested_keys_fail_closed():
    with pytest.raises(ValueError, match="coverage"):
        replace(_authority(), coverage_status="NOT_ASSESSED").validated()
    data = _authority().to_dict()
    data["claims"][0]["unknown"] = "closed"
    with pytest.raises(ValueError, match="keys"):
        ClaimAuthority.from_dict(data)


def test_v3_construction_round_trip_and_fingerprint_participation():
    profile = _profile()
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3
    assert profile.to_dict()["claim_authority"] == profile.claim_authority.to_dict()
    assert profile.profile_fingerprint == fingerprint(profile._body())
    assert NativeMissionProfile.from_dict(profile.to_dict()) == profile
    assert canonical_bytes(NativeMissionProfile.from_dict(profile.to_dict()).to_dict()) == canonical_bytes(profile.to_dict())


def test_predicates_separate_nested_shape_from_launchability():
    v1 = FLAGSHIP_INCIDENT_REPLAY_PROFILE
    v3 = _profile()
    v2_data = v3.to_dict()
    v2_data["schema_version"] = "admissible_native_mission_profile_v2"
    v2_data.pop("claim_authority")
    v2 = NativeMissionProfile.from_dict(_refingerprint(v2_data))
    assert (v1.has_nested_runtime_authority, v1.is_launchable_runtime_profile) == (False, False)
    assert (v2.has_nested_runtime_authority, v2.is_launchable_runtime_profile) == (True, True)
    assert (v3.has_nested_runtime_authority, v3.is_launchable_runtime_profile) == (True, False)


def test_v3_runtime_prompt_session_and_document_loading_fail_closed(tmp_path):
    v3 = _profile()
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        create_canary_session(session_id=v3.session_id, profile=v3)

    v2_data = v3.to_dict()
    v2_data["schema_version"] = "admissible_native_mission_profile_v2"
    v2_data.pop("claim_authority")
    v2 = NativeMissionProfile.from_dict(_refingerprint(v2_data))
    state = create_canary_session(session_id=v2.session_id, profile=v2)
    v2_prompt = build_native_agent_prompt(
        mission=state.mission, gate_contract=state.current_gate,
        work_workspace=tmp_path.resolve(), profile=v2,
    )
    assert "Permitted effects:" in v2_prompt
    assert "Exact stop clause:" in v2_prompt
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        build_native_agent_prompt(
            mission=state.mission, gate_contract=state.current_gate,
            work_workspace=tmp_path.resolve(), profile=v3,
        )

    document = tmp_path / "v3.json"
    document.write_text(json.dumps(v3.to_dict()), encoding="utf-8")
    with pytest.raises(ValueError, match="v2 schema"):
        load_native_mission_profile_document(document.resolve())

    with pytest.raises(ValueError, match="launchable runtime-v2"):
        observe_initialized_workspace_identity(v3)
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        run_native_mission_application(
            source_repository=tmp_path,
            required_source_head="0" * 40,
            run_root=tmp_path / "run",
            run_id=v3.run_id,
            session_id=v3.session_id,
            executable="unreachable-provider",
            profile=v3,
            preflight_only=True,
        )


def test_v3_coordinator_construction_refuses_before_state_executor_or_evidence(tmp_path):
    class UntouchedStore:
        phase = Phase.READY_FOR_GATE
        revision = 0
        events = ()

        def __getattribute__(self, name):
            if name in {"phase", "revision", "events"}:
                return object.__getattribute__(self, name)
            raise AssertionError(f"delegated store was touched through {name}")

    class UntouchedDependency:
        def __getattribute__(self, name):
            raise AssertionError(f"dependency was touched through {name}")

    session_store = UntouchedStore()
    execution_store = UntouchedDependency()
    executor = UntouchedDependency()
    backend = UntouchedDependency()
    evidence = tmp_path / "must-not-exist-evidence"
    coordinator = NativeCanaryCoordinator.__new__(NativeCanaryCoordinator)

    with mock.patch(
        "admissible.delegated_gate.native_canary.NativeCanaryOutcome",
        side_effect=AssertionError("no outcome may be emitted"),
    ), pytest.raises(ValueError, match="coordinator requires the launchable runtime-v2 schema"):
        NativeCanaryCoordinator.__init__(
            coordinator,
            session_store=session_store,
            execution_store=execution_store,
            executor=executor,
            backend_attestation=backend,
            source_repository=tmp_path / "source",
            work_workspace=tmp_path / "work",
            canary_parent=tmp_path / "parent",
            evidence_directory=evidence,
            profile=_profile(),
        )

    assert (session_store.phase, session_store.revision, session_store.events) == (
        Phase.READY_FOR_GATE, 0, (),
    )
    assert "profile" not in coordinator.__dict__
    assert "_profile_cache" not in coordinator.__dict__
    assert not evidence.exists()


def test_v3_outcome_defense_in_depth_refuses_without_emitting_outcome():
    coordinator = NativeCanaryCoordinator.__new__(NativeCanaryCoordinator)
    coordinator._profile_cache = _profile()
    coordinator.execution_store = mock.Mock()
    state = mock.Mock(session_id="claim-model-run", phase=Phase.READY_FOR_GATE, checkpoint_history=())
    with mock.patch(
        "admissible.delegated_gate.native_canary.NativeCanaryOutcome",
        side_effect=AssertionError("no outcome may be emitted"),
    ), pytest.raises(ValueError, match="outcome requires the launchable runtime-v2 schema"):
        coordinator._outcome(
            status=NativeCanaryStatus.DURABILITY_UNCERTAIN,
            state=state,
            detail="unreachable",
        )


def test_v4_authorization_rejects_v3_at_schema_guard_and_accepts_v2(tmp_path):
    from test_admissible_workflow_recovery_profile import _payload_harness

    v3 = _profile()
    v2_data = v3.to_dict()
    v2_data["schema_version"] = "admissible_native_mission_profile_v2"
    v2_data.pop("claim_authority")
    v2 = NativeMissionProfile.from_dict(_refingerprint(v2_data))
    harness = _payload_harness(tmp_path, v2)
    assert harness.payload.validated() is harness.payload

    candidate = replace(harness.payload, mission_profile=v3)
    preflight = tmp_path / "durable-preflight-evidence.json"

    with mock.patch(
        "admissible.delegated_gate.native_canary.create_canary_session",
        side_effect=AssertionError("V3 reached derived authorization fingerprints"),
    ), mock.patch.dict(os.environ, {"ADMISSIBLE_NATIVE_OWNER_AUTHORIZATION_DIGEST": ""}), pytest.raises(
        ValueError, match="runtime-v4 authorization requires the launchable runtime-v2 schema"
    ):
        candidate.validated()

    assert candidate.payload_fingerprint == harness.payload.payload_fingerprint
    assert "ADMISSIBLE_NATIVE_OWNER_AUTHORIZATION_DIGEST" not in os.environ
    assert not preflight.exists()


def test_claim_authority_identity_and_order_fingerprints_are_derived_and_order_sensitive():
    first = _claim("first", non_claims=("one", "two"))
    second = _claim("second")
    claims_a = _authority(claims=(first, second))
    claims_b = _authority(claims=(second, first))
    assert _profile(claims_a).profile_fingerprint != _profile(claims_b).profile_fingerprint

    non_claims_reordered = _authority(claims=(replace(first, non_claims=("two", "one")), second))
    assert _profile(claims_a).profile_fingerprint != _profile(non_claims_reordered).profile_fingerprint

    dependency_targets = (_claim("root", depends_on=("left", "right")), _claim("left"), _claim("right"))
    dependencies_reordered = (replace(dependency_targets[0], depends_on=("right", "left")),) + dependency_targets[1:]
    assert _profile(_authority(claims=dependency_targets)).profile_fingerprint != _profile(_authority(claims=dependencies_reordered)).profile_fingerprint

    authority = claims_a.validated()
    assert "identity_fingerprint" not in authority.to_dict()
    assert authority.identity_fingerprint == authority.identity_fingerprint == fingerprint(authority.to_dict())
    assert authority.identity_fingerprint != non_claims_reordered.validated().identity_fingerprint


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
