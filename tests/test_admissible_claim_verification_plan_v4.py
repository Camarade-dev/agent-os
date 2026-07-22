from __future__ import annotations

from dataclasses import replace
import json
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.mission_profile import (
    ClaimVerificationPlanAuthority,
    MAX_CLAIM_REFERENCES_PER_OBLIGATION,
    MAX_NEGATIVE_CONTROLS_PER_OBLIGATION,
    MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION,
    MAX_REFERENCE_CASES_PER_OBLIGATION,
    MAX_VERIFICATION_OBLIGATIONS,
    MISSION_PROFILE_SCHEMA_VERSION_V4,
    NativeMissionProfile,
    VerificationAcceptancePredicate,
    VerificationIndependenceRequirements,
    VerificationNegativeControl,
    VerificationObligation,
    VerificationPlanAuthorship,
    VerificationPlanCoverageStatus,
    VerificationStrategy,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.native_canary import (
    NativeCanaryCoordinator,
    NativeCanaryStatus,
    build_native_agent_prompt,
    create_canary_session,
    observe_initialized_workspace_identity,
    run_native_mission_application,
)
from admissible.delegated_gate.state import Phase
from test_admissible_claim_authority_v3 import _profile as _v3_profile, _refingerprint


def _independence(**changes):
    values = dict(temporal=True, artifact=True, process=True, information=False,
                  model=True, organizational=True)
    values.update(changes)
    return VerificationIndependenceRequirements(**values)


def _control(control_id="negative.one", description="The verifier rejects a known-bad result."):
    return VerificationNegativeControl(control_id, description)


def _obligation(obligation_id="verify.one", claim_ids=("claim.one",), **changes):
    values = dict(
        obligation_id=obligation_id,
        claim_ids=claim_ids,
        strategy=VerificationStrategy.CHECKPOINT_COMMAND,
        procedure_reference="checkpoint.tests",
        acceptance_predicate=VerificationAcceptancePredicate.EXIT_CODE_ZERO,
        declared_coverage="Exercises the authorized bounded behavior.",
        non_claims=("Does not establish complete mission coverage.", "Does not adjudicate the claim."),
        oracle_disclosed_to_subject=False,
        independence_requirements=_independence(),
        negative_controls=(_control(), _control("negative.two", "Rejects another known-bad result.")),
        reference_cases=("case.one", "case.two"),
    )
    values.update(changes)
    return VerificationObligation(**values)


def _plan(obligations=None, authorship=VerificationPlanAuthorship.OWNER_AUTHORED):
    return ClaimVerificationPlanAuthority(
        authorship,
        VerificationPlanCoverageStatus.NOT_ASSESSED,
        obligations or (_obligation(),),
    )


def _profile(plan=None, authority=None):
    v3 = _v3_profile(authority)
    values = dict(v3.__dict__)
    values.pop("profile_fingerprint")
    values.pop("schema_version")
    values.pop("claim_verification_plan_authority")
    return create_native_mission_profile(
        **values,
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V4,
        claim_verification_plan_authority=plan or _plan(),
    )


def _v2_profile():
    data = _v3_profile().to_dict()
    data["schema_version"] = "admissible_native_mission_profile_v2"
    data.pop("claim_authority")
    return NativeMissionProfile.from_dict(_refingerprint(data))


@pytest.mark.parametrize("authorship", list(VerificationPlanAuthorship))
def test_plan_authorship_values_round_trip(authorship):
    plan = _plan(authorship=authorship)
    assert ClaimVerificationPlanAuthority.from_dict(plan.to_dict()) == plan.validated()


@pytest.mark.parametrize("strategy,predicate", [
    (VerificationStrategy.CHECKPOINT_COMMAND, VerificationAcceptancePredicate.EXIT_CODE_ZERO),
    (VerificationStrategy.FROZEN_BEHAVIORAL_VERIFIER, VerificationAcceptancePredicate.EXIT_CODE_ZERO),
    (VerificationStrategy.HUMAN_RUBRIC_OBSERVATION, VerificationAcceptancePredicate.HUMAN_RUBRIC_PASS),
])
def test_exact_strategy_predicate_matrix_is_accepted(strategy, predicate):
    assert replace(_obligation(), strategy=strategy, acceptance_predicate=predicate).validated()


@pytest.mark.parametrize("strategy,predicate", [
    (VerificationStrategy.CHECKPOINT_COMMAND, VerificationAcceptancePredicate.HUMAN_RUBRIC_PASS),
    (VerificationStrategy.FROZEN_BEHAVIORAL_VERIFIER, VerificationAcceptancePredicate.HUMAN_RUBRIC_PASS),
    (VerificationStrategy.HUMAN_RUBRIC_OBSERVATION, VerificationAcceptancePredicate.EXIT_CODE_ZERO),
])
def test_every_other_strategy_predicate_pair_fails_closed(strategy, predicate):
    with pytest.raises(ValueError, match="incompatible"):
        replace(_obligation(), strategy=strategy, acceptance_predicate=predicate).validated()


def test_unsupported_enums_and_complete_coverage_fail_closed():
    data = _plan().to_dict()
    data["authorship"] = "MODEL_GENERATED"
    with pytest.raises(ValueError, match="authorship"):
        ClaimVerificationPlanAuthority.from_dict(data)
    data = _plan().to_dict()
    data["coverage_status"] = "COMPLETE"
    with pytest.raises(ValueError, match="NOT_ASSESSED"):
        ClaimVerificationPlanAuthority.from_dict(data)
    data = _obligation().to_dict()
    data["strategy"] = "EXECUTED"
    with pytest.raises(ValueError, match="strategy"):
        VerificationObligation.from_dict(data)


@pytest.mark.parametrize("field", list(VerificationIndependenceRequirements.__dataclass_fields__))
@pytest.mark.parametrize("invalid", [0, 1, "true", None])
def test_independence_fields_are_strict_booleans(field, invalid):
    with pytest.raises(ValueError, match="boolean"):
        replace(_independence(), **{field: invalid}).validated()


@pytest.mark.parametrize("invalid", [0, 1, "false", None])
def test_oracle_disclosure_is_a_strict_boolean(invalid):
    with pytest.raises(ValueError, match="boolean"):
        replace(_obligation(), oracle_disclosed_to_subject=invalid).validated()


def test_oracle_disclosure_cannot_require_information_independence():
    with pytest.raises(ValueError, match="incompatible"):
        replace(_obligation(), oracle_disclosed_to_subject=True,
                independence_requirements=_independence(information=True)).validated()
    assert replace(_obligation(), oracle_disclosed_to_subject=True).validated()


@pytest.mark.parametrize("factory", [_independence, _control, _obligation, _plan])
def test_every_nested_object_rejects_unknown_and_missing_keys(factory):
    data = factory().to_dict()
    cls = type(factory())
    data["unknown"] = True
    with pytest.raises(ValueError, match="keys"):
        cls.from_dict(data)
    data = factory().to_dict()
    data.pop(next(iter(data)))
    with pytest.raises(ValueError, match="keys"):
        cls.from_dict(data)


@pytest.mark.parametrize("control_id", ["", "unsafe id", "../control"])
def test_negative_control_identifier_is_canonical(control_id):
    with pytest.raises(ValueError, match="identifier"):
        _control(control_id).validated()


@pytest.mark.parametrize("description", ["", " ", "x" * 65537], ids=["empty", "blank", "oversized"])
def test_negative_control_description_is_bounded_semantic_text(description):
    with pytest.raises(ValueError):
        _control(description=description).validated()


def test_obligation_identifiers_text_uniqueness_and_order_round_trip():
    obligation = _obligation()
    loaded = VerificationObligation.from_dict(obligation.to_dict())
    assert loaded == obligation.validated()
    assert loaded.non_claims == obligation.non_claims
    assert loaded.negative_controls == obligation.negative_controls
    assert loaded.reference_cases == obligation.reference_cases
    for changed in (
        replace(obligation, obligation_id="bad id"),
        replace(obligation, procedure_reference="../command"),
        replace(obligation, declared_coverage=""),
        replace(obligation, claim_ids=("claim.one", "claim.one")),
        replace(obligation, non_claims=("same", "same")),
        replace(obligation, negative_controls=(_control(), _control())),
        replace(obligation, reference_cases=("case.one", "case.one")),
    ):
        with pytest.raises(ValueError):
            changed.validated()


@pytest.mark.parametrize("field,limit,make", [
    ("claim_ids", MAX_CLAIM_REFERENCES_PER_OBLIGATION, lambda i: f"claim.{i}"),
    ("non_claims", MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION, lambda i: f"Excluded {i}"),
    ("negative_controls", MAX_NEGATIVE_CONTROLS_PER_OBLIGATION, lambda i: _control(f"control.{i}", f"Control {i}")),
    ("reference_cases", MAX_REFERENCE_CASES_PER_OBLIGATION, lambda i: f"case.{i}"),
])
def test_obligation_collection_bounds_are_exact(field, limit, make):
    values = tuple(make(i) for i in range(limit))
    assert replace(_obligation(), **{field: values}).validated()
    with pytest.raises(ValueError, match="cannot exceed"):
        replace(_obligation(), **{field: values + (make(limit),)}).validated()


def test_plan_bounds_duplicate_ids_and_order_are_authoritative():
    obligations = tuple(_obligation(f"verify.{i}") for i in range(MAX_VERIFICATION_OBLIGATIONS))
    assert _plan(obligations).validated().verification_obligations == obligations
    with pytest.raises(ValueError, match="cannot exceed"):
        _plan(obligations + (_obligation("verify.overflow"),)).validated()
    with pytest.raises(ValueError, match="unique"):
        _plan((_obligation(), _obligation())).validated()
    assert ClaimVerificationPlanAuthority.from_dict(_plan(obligations[:2]).to_dict()).verification_obligations == obligations[:2]
    with pytest.raises(ValueError, match="non-empty"):
        replace(_plan(), verification_obligations=()).validated()
    with pytest.raises(ValueError, match="non-empty"):
        replace(_obligation(), claim_ids=()).validated()


def test_v4_construction_embedding_round_trip_and_structural_predicates():
    profile = _profile()
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4
    assert profile.has_nested_runtime_authority is True
    assert profile.is_launchable_runtime_profile is False
    assert profile.is_runtime_profile is False
    assert profile.to_dict()["claim_verification_plan_authority"] == profile.claim_verification_plan_authority.to_dict()
    assert NativeMissionProfile.from_dict(profile.to_dict()) == profile
    assert canonical_bytes(NativeMissionProfile.from_dict(profile.to_dict()).to_dict()) == canonical_bytes(profile.to_dict())


def test_v4_claim_plan_cross_validation_cardinalities():
    assert _profile(_plan((_obligation("one"), _obligation("two")))).validated()
    assert _profile(_plan((_obligation(claim_ids=("claim.one", "claim.two")),)),
                    authority=replace(_v3_profile().claim_authority,
                                      claims=(_v3_profile().claim_authority.claims[0],
                                              replace(_v3_profile().claim_authority.claims[0], claim_id="claim.two")))).validated()
    with pytest.raises(ValueError, match="missing"):
        _profile(_plan((_obligation(claim_ids=("absent",)),)))


def test_v4_allows_uncovered_claims_while_not_assessed():
    base = _v3_profile().claim_authority.claims[0]
    authority = replace(_v3_profile().claim_authority,
                        claims=(base, replace(base, claim_id="claim.uncovered")))
    assert _profile(authority=authority).validated()


def test_plan_content_and_owner_order_each_change_profile_fingerprint():
    first = _obligation("first")
    second = _obligation("second", claim_ids=("claim.one",))
    baseline = _profile(_plan((first, second)))
    mutations = [
        _plan((second, first)),
        _plan((replace(first, claim_ids=("claim.two", "claim.one")), second)),
        _plan((replace(first, strategy=VerificationStrategy.FROZEN_BEHAVIORAL_VERIFIER), second)),
        _plan((replace(first, strategy=VerificationStrategy.HUMAN_RUBRIC_OBSERVATION,
                       acceptance_predicate=VerificationAcceptancePredicate.HUMAN_RUBRIC_PASS), second)),
        _plan((replace(first, non_claims=tuple(reversed(first.non_claims))), second)),
        _plan((replace(first, non_claims=("Changed exclusion.", first.non_claims[1])), second)),
        _plan((replace(first, negative_controls=tuple(reversed(first.negative_controls))), second)),
        _plan((replace(first, negative_controls=(replace(first.negative_controls[0],
                                                         description="Changed control."),
                                                   first.negative_controls[1])), second)),
        _plan((replace(first, reference_cases=tuple(reversed(first.reference_cases))), second)),
        _plan((replace(first, reference_cases=("case.changed", first.reference_cases[1])), second)),
        _plan((replace(first, obligation_id="changed"), second)),
        _plan((replace(first, procedure_reference="changed.procedure"), second)),
        _plan((replace(first, declared_coverage="Changed coverage."), second)),
        _plan((replace(first, oracle_disclosed_to_subject=True), second)),
        _plan((first, second), VerificationPlanAuthorship.TEMPLATE_AUTHORED),
    ]
    authority = _v3_profile().claim_authority
    claim = authority.claims[0]
    two_claims = replace(authority, claims=(claim, replace(claim, claim_id="claim.two")))
    assert all(_profile(plan, two_claims).profile_fingerprint != _profile(_plan((first, second)), two_claims).profile_fingerprint for plan in mutations)
    for field in VerificationIndependenceRequirements.__dataclass_fields__:
        changed = replace(first, independence_requirements=replace(first.independence_requirements,
                                                                    **{field: not getattr(first.independence_requirements, field)}))
        assert _profile(_plan((changed, second))).profile_fingerprint != baseline.profile_fingerprint


def test_v4_missing_null_malformed_unknown_and_v3_injection_fail_closed():
    valid = _profile().to_dict()
    mutations = [
        lambda d: d.pop("claim_verification_plan_authority"),
        lambda d: d.update(claim_verification_plan_authority=None),
        lambda d: d.update(claim_verification_plan_authority=[]),
        lambda d: d.update(unknown=True),
        lambda d: d["claim_verification_plan_authority"].update(unknown=True),
        lambda d: d["claim_verification_plan_authority"]["verification_obligations"][0].update(unknown=True),
    ]
    for mutation in mutations:
        data = json.loads(json.dumps(valid))
        mutation(data)
        with pytest.raises((ValueError, TypeError)):
            NativeMissionProfile.from_dict(data)
    v3 = _v3_profile().to_dict()
    v3["claim_verification_plan_authority"] = _plan().to_dict()
    with pytest.raises(ValueError, match="keys"):
        NativeMissionProfile.from_dict(v3)


def test_v4_refuses_prompt_session_document_observation_and_application_before_side_effect(tmp_path):
    v4 = _profile()
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        create_canary_session(session_id=v4.session_id, profile=v4)
    state = create_canary_session(session_id=_v2_profile().session_id, profile=_v2_profile())
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        build_native_agent_prompt(mission=state.mission, gate_contract=state.current_gate,
                                  work_workspace=tmp_path, profile=v4)
    document = tmp_path / "v4.json"
    document.write_text(json.dumps(v4.to_dict()), encoding="utf-8")
    with pytest.raises(ValueError, match="v2 schema"):
        load_native_mission_profile_document(document.resolve())
    with mock.patch("admissible.delegated_gate.native_canary.subprocess.run",
                    side_effect=AssertionError("process reached")):
        with pytest.raises(ValueError, match="launchable runtime-v2"):
            observe_initialized_workspace_identity(v4)
        with pytest.raises(ValueError, match="launchable runtime-v2"):
            run_native_mission_application(source_repository=tmp_path / "source",
                required_source_head="0" * 40, run_root=tmp_path / "run", run_id=v4.run_id,
                session_id=v4.session_id, executable="unreachable", profile=v4, preflight_only=True)
    assert not (tmp_path / "run").exists()


def test_v4_coordinator_and_outcome_refuse_before_dependencies(tmp_path):
    class Untouched:
        phase = Phase.READY_FOR_GATE
        revision = 0
        events = ()
        def __getattribute__(self, name):
            if name in {"phase", "revision", "events"}:
                return object.__getattribute__(self, name)
            raise AssertionError(f"dependency touched: {name}")
    coordinator = NativeCanaryCoordinator.__new__(NativeCanaryCoordinator)
    untouched = Untouched()
    with pytest.raises(ValueError, match="coordinator requires the launchable runtime-v2 schema"):
        NativeCanaryCoordinator.__init__(coordinator, session_store=untouched,
            execution_store=untouched, executor=untouched, backend_attestation=untouched,
            source_repository=tmp_path / "source", work_workspace=tmp_path / "work",
            canary_parent=tmp_path / "parent", evidence_directory=tmp_path / "evidence",
            profile=_profile())
    coordinator._profile_cache = _profile()
    coordinator.execution_store = mock.Mock()
    with pytest.raises(ValueError, match="outcome requires the launchable runtime-v2 schema"):
        coordinator._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,
                             state=mock.Mock(session_id="v4", phase=Phase.READY_FOR_GATE,
                                             checkpoint_history=()), detail="unreachable")


def test_runtime_v4_authorization_payload_refuses_canonical_profile_before_derivation(tmp_path):
    from test_admissible_workflow_recovery_profile import _payload_harness

    harness = _payload_harness(tmp_path, _v2_profile())
    candidate = replace(harness.payload, mission_profile=_profile())
    with mock.patch(
        "admissible.delegated_gate.native_canary.create_canary_session",
        side_effect=AssertionError("V4 reached authorization derivation"),
    ), pytest.raises(ValueError, match="runtime-v4 authorization requires the launchable runtime-v2 schema"):
        candidate.validated()
    assert candidate.payload_fingerprint == harness.payload.payload_fingerprint
