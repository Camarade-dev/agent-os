from __future__ import annotations

from dataclasses import replace
import json
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import (
    MAX_VERIFICATION_EVIDENCE_BINDINGS,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
    ProfileCheckpointCommand,
    VerificationAcceptancePredicate,
    VerificationAuthority,
    VerificationEvidenceBinding,
    VerificationEvidenceBindingAuthority,
    VerificationEvidenceBindingAuthorship,
    VerificationEvidenceBindingCoverageStatus,
    VerificationEvidenceSourceAuthorityType,
    VerificationMode,
    VerificationStrategy,
    create_native_mission_profile,
)
from admissible.delegated_gate.models import EvidenceKind
from test_admissible_claim_verification_plan_v4 import _obligation, _plan, _profile as _v4_profile
from test_admissible_claim_verification_plan_v4 import _v2_profile
from admissible.delegated_gate.mission_profile import load_native_mission_profile_document
from admissible.delegated_gate.native_canary import (
    NativeCanaryCoordinator, NativeCanaryStatus, build_native_agent_prompt,
    create_canary_session, observe_initialized_workspace_identity,
    run_native_mission_application,
)
from admissible.delegated_gate.state import Phase


SOURCE = "def verify(workspace):\n    return True\n"
SOURCE_SHA = "6edc3f1c11602a822296c74c345cb95255b2c57bcc1eecbb73b18209d0b4690d"


def _binding(binding_id="binding.one", obligation_id="verify.one", **changes):
    values = dict(
        binding_id=binding_id,
        obligation_id=obligation_id,
        source_authority_type=VerificationEvidenceSourceAuthorityType.CHECKPOINT_COMMAND_AUTHORITY,
        source_authority_reference="checkpoint.tests",
    )
    values.update(changes)
    return VerificationEvidenceBinding(**values)


def _bindings(items=None, authorship=VerificationEvidenceBindingAuthorship.OWNER_AUTHORED):
    return VerificationEvidenceBindingAuthority(
        authorship,
        VerificationEvidenceBindingCoverageStatus.NOT_ASSESSED,
        items or (_binding(),),
    )


def _profile(plan=None, bindings=None, *, frozen=False):
    base = _v4_profile(plan=plan)
    values = dict(base.__dict__)
    for key in ("schema_version", "profile_fingerprint", "verification_evidence_binding_authority"):
        values.pop(key, None)
    if frozen:
        verification = VerificationAuthority(
            VerificationMode.FROZEN_BEHAVIORAL, SOURCE, SOURCE_SHA, 30, 8192, True
        )
        values.update(
            verification=verification,
            verifier_source=SOURCE,
            verifier_source_sha256=SOURCE_SHA,
            verifier_timeout_seconds=30,
            verifier_output_limit_bytes=8192,
        )
    else:
        values.update(
            required_evidence_kinds=values["required_evidence_kinds"] + (EvidenceKind.VERIFICATION_COMMAND.value,),
            checkpoint_commands=(ProfileCheckpointCommand("checkpoint.tests", ("python", "-m", "pytest"), 30, 8192),),
        )
    return create_native_mission_profile(
        **values,
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V5,
        verification_evidence_binding_authority=bindings or _bindings(),
    )


@pytest.mark.parametrize("authorship", list(VerificationEvidenceBindingAuthorship))
def test_binding_authorship_values_and_ordered_round_trip(authorship):
    authority = _bindings((_binding("one"), _binding("two", "verify.two")), authorship)
    loaded = VerificationEvidenceBindingAuthority.from_dict(authority.to_dict())
    assert loaded == authority.validated()
    assert loaded.bindings == authority.bindings
    assert "identity_fingerprint" not in loaded.to_dict()


def test_exact_enums_and_exact_key_law_fail_closed():
    assert {item.value for item in VerificationEvidenceBindingCoverageStatus} == {"NOT_ASSESSED"}
    assert {item.value for item in VerificationEvidenceSourceAuthorityType} == {
        "CHECKPOINT_COMMAND_AUTHORITY", "FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY"
    }
    for field in ("evidence_id", "eligibility", "passed", "human_disposition", "product_verdict"):
        data = _binding().to_dict(); data[field] = "forbidden"
        with pytest.raises(ValueError, match="keys"):
            VerificationEvidenceBinding.from_dict(data)
    data = _bindings().to_dict(); data["coverage_status"] = "COMPLETE"
    with pytest.raises(ValueError, match="NOT_ASSESSED"):
        VerificationEvidenceBindingAuthority.from_dict(data)
    data = _binding().to_dict(); data["source_authority_type"] = "HUMAN_RUBRIC_OBSERVATION"
    with pytest.raises(ValueError, match="type"):
        VerificationEvidenceBinding.from_dict(data)


@pytest.mark.parametrize("field,value", [
    ("binding_id", "bad id"), ("obligation_id", "../bad"),
    ("source_authority_reference", "Bad Command"),
])
def test_checkpoint_binding_identifiers_are_canonical_strict_strings(field, value):
    with pytest.raises(ValueError, match="identifier"):
        replace(_binding(), **{field: value}).validated()


def test_behavioral_reference_requires_exact_sha256():
    with pytest.raises(ValueError, match="SHA-256"):
        replace(_binding(), source_authority_type=VerificationEvidenceSourceAuthorityType.FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY,
                source_authority_reference="not-a-digest").validated()


def test_binding_bounds_uniqueness_and_singular_obligation_shape():
    items = tuple(_binding(f"binding.{i}", f"verify.{i}") for i in range(MAX_VERIFICATION_EVIDENCE_BINDINGS))
    assert _bindings(items).validated().bindings == items
    with pytest.raises(ValueError, match="cannot exceed"):
        _bindings(items + (_binding("overflow", "overflow"),)).validated()
    with pytest.raises(ValueError, match="identities must be unique"):
        _bindings((_binding(), _binding())).validated()
    with pytest.raises(ValueError, match="obligation identities must be unique"):
        _bindings((_binding(), _binding("other"))).validated()
    with pytest.raises(ValueError, match="non-empty"):
        replace(_bindings(), bindings=()).validated()
    data = _binding().to_dict(); data["obligation_ids"] = [data.pop("obligation_id")]
    with pytest.raises(ValueError, match="keys"):
        VerificationEvidenceBinding.from_dict(data)


def test_valid_checkpoint_binding_and_direct_source_resolution_only():
    assert _profile().validated()
    for reference in ("absent.command", "Checkpoint.Tests"):
        with pytest.raises(ValueError, match="missing from profile"):
            _profile(bindings=_bindings((_binding(source_authority_reference=reference),)))
    plan = _plan((_obligation(procedure_reference="absent.command"),))
    with pytest.raises(ValueError, match="missing from profile"):
        _profile(plan, _bindings((_binding(source_authority_reference="absent.command"),)))


def test_frozen_behavioral_binding_is_content_addressed_and_mode_bound():
    obligation = _obligation(strategy=VerificationStrategy.FROZEN_BEHAVIORAL_VERIFIER,
                             oracle_disclosed_to_subject=True)
    binding = _binding(
        source_authority_type=VerificationEvidenceSourceAuthorityType.FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY,
        source_authority_reference=SOURCE_SHA,
    )
    assert _profile(_plan((obligation,)), _bindings((binding,)), frozen=True)
    with pytest.raises(ValueError, match="contradicts"):
        _profile(_plan((obligation,)), _bindings((replace(binding, source_authority_reference="0" * 64),)), frozen=True)
    with pytest.raises(ValueError, match="requires frozen"):
        _profile(_plan((obligation,)), _bindings((binding,)))


def test_strategy_compatibility_human_rejection_and_partial_coverage():
    human = _obligation("human", strategy=VerificationStrategy.HUMAN_RUBRIC_OBSERVATION,
                        acceptance_predicate=VerificationAcceptancePredicate.HUMAN_RUBRIC_PASS)
    automated = _obligation("automated")
    assert _profile(_plan((automated, human)), _bindings((_binding(obligation_id="automated"),)))
    assert _profile(_plan((automated, _obligation("unbound"))), _bindings((_binding(obligation_id="automated"),)))
    with pytest.raises(ValueError, match="human-rubric"):
        _profile(_plan((automated, human)), _bindings((_binding(obligation_id="human"),)))
    with pytest.raises(ValueError, match="incompatible"):
        _profile(bindings=_bindings((_binding(source_authority_type=VerificationEvidenceSourceAuthorityType.FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY,
                                               source_authority_reference="0" * 64),)))


def test_source_reuse_for_distinct_obligations_and_unknown_obligation_rejection():
    plan = _plan((_obligation("one"), _obligation("two")))
    bindings = _bindings((_binding("first", "one"), _binding("second", "two")))
    assert _profile(plan, bindings)
    with pytest.raises(ValueError, match="obligation reference is missing"):
        _profile(bindings=_bindings((_binding(obligation_id="absent"),)))


def test_v5_shape_round_trip_predicates_and_v4_rejects_injection():
    profile = _profile()
    assert (profile.has_nested_runtime_authority, profile.is_launchable_runtime_profile, profile.is_runtime_profile) == (True, False, False)
    assert NativeMissionProfile.from_dict(profile.to_dict()) == profile
    assert canonical_bytes(NativeMissionProfile.from_dict(profile.to_dict()).to_dict()) == canonical_bytes(profile.to_dict())
    assert profile.to_dict()["verification_evidence_binding_authority"] == profile.verification_evidence_binding_authority.to_dict()
    data = _v4_profile().to_dict(); data["verification_evidence_binding_authority"] = _bindings().to_dict()
    with pytest.raises(ValueError, match="keys"):
        NativeMissionProfile.from_dict(data)


def test_missing_null_malformed_and_unknown_v5_fields_fail_closed():
    for mutation in ("missing", "null", "malformed", "unknown"):
        data = _profile().to_dict()
        if mutation == "missing": data.pop("verification_evidence_binding_authority")
        elif mutation == "null": data["verification_evidence_binding_authority"] = None
        elif mutation == "malformed": data["verification_evidence_binding_authority"] = []
        else: data["unknown"] = True
        with pytest.raises((ValueError, TypeError)):
            NativeMissionProfile.from_dict(data)


def test_fingerprint_sensitive_to_every_binding_dimension_and_pure_order():
    plan = _plan((_obligation("one"), _obligation("two")))
    first, second = _binding("first", "one"), _binding("second", "two")
    baseline = _profile(plan, _bindings((first, second)))
    variants = (
        _bindings((second, first)),
        _bindings((replace(first, binding_id="changed"), second)),
        _bindings((replace(first, obligation_id="two"),)),
        _bindings((first,)),
        _bindings((first, second), VerificationEvidenceBindingAuthorship.TEMPLATE_AUTHORED),
    )
    assert all(_profile(plan, variant).profile_fingerprint != baseline.profile_fingerprint for variant in variants)
    assert _profile(plan, _bindings((first, second))).profile_fingerprint == baseline.profile_fingerprint
    assert "identity_fingerprint" not in baseline.to_dict()["verification_evidence_binding_authority"]


def test_authority_fingerprint_sensitive_to_source_type_reference_and_mapping_order():
    checkpoint = _bindings()
    behavioral_binding = replace(
        _binding(),
        source_authority_type=VerificationEvidenceSourceAuthorityType.FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY,
        source_authority_reference=SOURCE_SHA,
    )
    behavioral = _bindings((behavioral_binding,))
    changed_reference = _bindings((replace(behavioral_binding, source_authority_reference="0" * 64),))
    assert len({checkpoint.identity_fingerprint, behavioral.identity_fingerprint,
                changed_reference.identity_fingerprint}) == 3
    reversed_mapping = {
        key: value for key, value in reversed(list(checkpoint.to_dict().items()))
    }
    assert VerificationEvidenceBindingAuthority.from_dict(reversed_mapping) == checkpoint
    assert canonical_bytes(reversed_mapping) == canonical_bytes(checkpoint.to_dict())


def test_v5_refuses_every_runtime_entry_before_dependencies_or_mutation(tmp_path):
    v5 = _profile()
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        create_canary_session(session_id=v5.session_id, profile=v5)
    v2 = _v2_profile()
    state = create_canary_session(session_id=v2.session_id, profile=v2)
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        build_native_agent_prompt(mission=state.mission, gate_contract=state.current_gate,
                                  work_workspace=tmp_path, profile=v5)
    document = tmp_path / "v5.json"
    document.write_text(json.dumps(v5.to_dict()), encoding="utf-8")
    with pytest.raises(ValueError, match="v2 schema"):
        load_native_mission_profile_document(document.resolve())
    with mock.patch("admissible.delegated_gate.native_canary.subprocess.run",
                    side_effect=AssertionError("process reached")):
        with pytest.raises(ValueError, match="launchable runtime-v2"):
            observe_initialized_workspace_identity(v5)
        with pytest.raises(ValueError, match="launchable runtime-v2"):
            run_native_mission_application(source_repository=tmp_path / "source",
                required_source_head="0" * 40, run_root=tmp_path / "run", run_id=v5.run_id,
                session_id=v5.session_id, executable="unreachable", profile=v5, preflight_only=True)
    assert not (tmp_path / "run").exists()

    class Untouched:
        phase = Phase.READY_FOR_GATE
        revision = 0
        events = ()
        def __getattribute__(self, name):
            if name in {"phase", "revision", "events"}:
                return object.__getattribute__(self, name)
            raise AssertionError(f"dependency touched: {name}")
    untouched = Untouched()
    coordinator = NativeCanaryCoordinator.__new__(NativeCanaryCoordinator)
    with pytest.raises(ValueError, match="coordinator requires the launchable runtime-v2 schema"):
        NativeCanaryCoordinator.__init__(coordinator, session_store=untouched,
            execution_store=untouched, executor=untouched, backend_attestation=untouched,
            source_repository=tmp_path / "source", work_workspace=tmp_path / "work",
            canary_parent=tmp_path / "parent", evidence_directory=tmp_path / "evidence", profile=v5)
    coordinator._profile_cache = v5
    coordinator.execution_store = mock.Mock()
    with pytest.raises(ValueError, match="outcome requires the launchable runtime-v2 schema"):
        coordinator._outcome(status=NativeCanaryStatus.DURABILITY_UNCERTAIN,
            state=mock.Mock(session_id="v5", phase=Phase.READY_FOR_GATE, checkpoint_history=()),
            detail="unreachable")


def test_runtime_v4_authorization_payload_refuses_v5_before_derivation(tmp_path):
    from test_admissible_workflow_recovery_profile import _payload_harness
    harness = _payload_harness(tmp_path, _v2_profile())
    candidate = replace(harness.payload, mission_profile=_profile())
    with mock.patch("admissible.delegated_gate.native_canary.create_canary_session",
                    side_effect=AssertionError("V5 reached authorization derivation")), \
            pytest.raises(ValueError, match="runtime-v4 authorization requires the launchable runtime-v2 schema"):
        candidate.validated()
