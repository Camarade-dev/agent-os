from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import hashlib
import inspect
import io
import os
from pathlib import Path
import sys
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import (
    canonical_bytes,
    canonical_json,
)
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
    create_historical_evaluation_pairing_authority,
    derive_historical_v5_evaluation_profile,
    project_v5_runtime_authority_to_v2,
    require_exact_v5_v2_runtime_authority_compatibility,
)
from admissible.delegated_gate.mission_profile import (
    FLAGSHIP_INCIDENT_REPLAY_PROFILE,
    MAX_VERIFICATION_EVIDENCE_BINDINGS,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    ClaimAuthority,
    ClaimAuthorship,
    ClaimSetCoverageStatus,
    ClaimVerificationPlanAuthority,
    NativeMissionProfile,
    VerificationEvidenceBindingAuthority,
    VerificationEvidenceBindingAuthorship,
    VerificationEvidenceBindingCoverageStatus,
    VerificationPlanAuthorship,
    VerificationPlanCoverageStatus,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from test_admissible_claim_authority_v3 import _profile as _v3_profile
from test_admissible_claim_verification_plan_v4 import _profile as _v4_profile
from test_admissible_historical_evaluation_pairing import (
    _evaluation_profile,
    _payload_for_runtime_profile,
    _refingerprint_payload,
    _refingerprint_profile,
    _runtime_profile_variant,
)
from test_admissible_verification_evidence_binding_v5 import _profile as _v5_profile
from test_admissible_workflow_recovery_profile import _payload_harness


# ---------------------------------------------------------------------------
# Fixtures: one deliberately order-observable historical runtime-V2 payload.
# Clause, checkpoint, claim, obligation, and binding orders are all
# non-alphabetical so any silent sort or normalization changes canonical bytes.
# ---------------------------------------------------------------------------


HOSTILE_MISSION_TEXT = "  MiXeD Mission\tText\nSecond  line with  spaces  "
HOSTILE_GATE_OBJECTIVE = "\tPreserve  Exact CASE\nAnd spacing\t"
HOSTILE_COMPLETION_CONDITIONS_TEXT = "  Complete only when:\n\tA  and  B\n  "
HOSTILE_STOP_CLAUSE = "\nSTOP  exactly\twhen authorized.\nDo  not trim.  "

HOSTILE_RUNTIME_TEXT = {
    "mission_text": HOSTILE_MISSION_TEXT,
    "gate_objective": HOSTILE_GATE_OBJECTIVE,
    "completion_conditions_text": HOSTILE_COMPLETION_CONDITIONS_TEXT,
}


def _assert_hostile_runtime_text_mapping(data: dict) -> None:
    encoded = canonical_bytes(data)
    for field, expected in HOSTILE_RUNTIME_TEXT.items():
        assert data[field] == expected
        assert canonical_bytes({field: data[field]}) == canonical_bytes(
            {field: expected}
        )
        assert canonical_bytes({field: expected})[1:-1] in encoded
    assert data["runtime_prompt"]["stop_clause"] == HOSTILE_STOP_CLAUSE
    assert canonical_bytes(
        {"stop_clause": data["runtime_prompt"]["stop_clause"]}
    ) == canonical_bytes({"stop_clause": HOSTILE_STOP_CLAUSE})
    assert canonical_bytes({"stop_clause": HOSTILE_STOP_CLAUSE})[1:-1] in encoded


def _runtime_v2_profile() -> NativeMissionProfile:
    base = project_v5_runtime_authority_to_v2(_evaluation_profile()).to_dict()
    base.update(HOSTILE_RUNTIME_TEXT)
    base["runtime_prompt"]["stop_clause"] = HOSTILE_STOP_CLAUSE
    base["gate_clauses"] = [
        ["clause.zulu", "The zulu clause is satisfied by the recorded material."],
        ["clause.alpha", "The alpha clause is satisfied by the recorded material."],
    ]
    base["checkpoint_commands"] = [
        {
            "command_id": "checkpoint.zeta",
            "argv": ["node", "scripts/zeta-check.js", "--strict"],
            "timeout_seconds": 45,
            "max_capture_bytes": 4096,
        },
        {
            "command_id": "checkpoint.alpha",
            "argv": ["python", "-m", "alpha_checks"],
            "timeout_seconds": 30,
            "max_capture_bytes": 8192,
        },
    ]
    return NativeMissionProfile.from_dict(_refingerprint_profile(base))


@pytest.fixture(scope="module")
def historical_payload_document(tmp_path_factory: pytest.TempPathFactory) -> dict:
    tmp_path = tmp_path_factory.mktemp("historical-derivation")
    runtime_profile = _runtime_v2_profile()
    live = _payload_harness(tmp_path, runtime_profile).payload.to_dict()
    absent = tmp_path / "absent-historical-resources"
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
    document = _refingerprint_payload(live)
    assert not absent.exists()
    return document


@pytest.fixture(scope="module")
def historical_payload(
    historical_payload_document: dict,
) -> NativeCanaryAuthorizationPayloadV4:
    return load_historical_native_canary_authorization_payload_v4(
        historical_payload_document
    )


# ---------------------------------------------------------------------------
# Owner-authored evaluation member arrays (fresh copies per call).
# ---------------------------------------------------------------------------


def _owner_claims() -> list[dict]:
    return [
        {
            "claim_id": "claim.zulu",
            "statement": "The zulu behavior exists in the recorded material.",
            "obligation_level": "MANDATORY",
            "depends_on": [],
            "non_claims": ["Does not assert the alpha behavior."],
        },
        {
            "claim_id": "claim.alpha",
            "statement": "The alpha behavior builds on the zulu behavior.",
            "obligation_level": "OPTIONAL",
            "depends_on": ["claim.zulu"],
            "non_claims": [],
        },
        {
            "claim_id": "claim.mike",
            "statement": "The mike observation was recorded during the run.",
            "obligation_level": "ADVISORY",
            "depends_on": [],
            "non_claims": [],
        },
    ]


def _independence(**changes) -> dict:
    values = dict(
        temporal=True,
        artifact=True,
        process=True,
        information=False,
        model=True,
        organizational=True,
    )
    values.update(changes)
    return values


def _obligation_member(
    obligation_id: str,
    claim_ids: list[str],
    strategy: str,
    procedure_reference: str,
    acceptance_predicate: str,
    **changes,
) -> dict:
    values = dict(
        obligation_id=obligation_id,
        claim_ids=claim_ids,
        strategy=strategy,
        procedure_reference=procedure_reference,
        acceptance_predicate=acceptance_predicate,
        declared_coverage="Exercises one bounded slice of the recorded behavior.",
        non_claims=["Does not adjudicate the claim."],
        oracle_disclosed_to_subject=False,
        independence_requirements=_independence(),
        negative_controls=[
            {
                "control_id": "negative.zulu",
                "description": "Rejects a known-bad recorded result.",
            }
        ],
        reference_cases=["case.zulu"],
    )
    values.update(changes)
    return values


def _owner_plan() -> list[dict]:
    # verify.zulu's procedure_reference deliberately names a real checkpoint
    # command while its binding references a different one: only the binding's
    # source_authority_reference may ever authorize a source.
    return [
        _obligation_member(
            "verify.zulu", ["claim.zulu"],
            "CHECKPOINT_COMMAND", "checkpoint.zeta", "EXIT_CODE_ZERO",
        ),
        _obligation_member(
            "verify.echo", ["claim.zulu", "claim.alpha"],
            "CHECKPOINT_COMMAND", "procedure.echo", "EXIT_CODE_ZERO",
        ),
        _obligation_member(
            "verify.alpha", ["claim.alpha"],
            "FROZEN_BEHAVIORAL_VERIFIER", "procedure.alpha", "EXIT_CODE_ZERO",
        ),
        _obligation_member(
            "verify.human", ["claim.mike"],
            "HUMAN_RUBRIC_OBSERVATION", "rubric.mike", "HUMAN_RUBRIC_PASS",
        ),
    ]


def _owner_bindings(verifier_digest: str) -> list[dict]:
    return [
        {
            "binding_id": "binding.zulu",
            "obligation_id": "verify.zulu",
            "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
            "source_authority_reference": "checkpoint.alpha",
        },
        {
            "binding_id": "binding.alpha",
            "obligation_id": "verify.alpha",
            "source_authority_type": "FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY",
            "source_authority_reference": verifier_digest,
        },
        {
            "binding_id": "binding.echo",
            "obligation_id": "verify.echo",
            "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
            "source_authority_reference": "checkpoint.zeta",
        },
    ]


def _derive(
    payload: NativeCanaryAuthorizationPayloadV4,
    **overrides,
) -> NativeMissionProfile:
    kwargs = dict(
        target_authorization_payload=payload,
        result_claims=_owner_claims(),
        claim_verification_plan=_owner_plan(),
        verification_evidence_bindings=_owner_bindings(
            payload.mission_profile.verification.verifier_source_sha256
        ),
    )
    kwargs.update(overrides)
    return derive_historical_v5_evaluation_profile(**kwargs)


@pytest.fixture(scope="module")
def derived_v5(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeMissionProfile:
    return _derive(historical_payload)


# ---------------------------------------------------------------------------
# Valid derivation.
# ---------------------------------------------------------------------------


def test_hostile_runtime_text_is_byte_preserved_across_historical_derivation(
    historical_payload_document: dict,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    for value in (*HOSTILE_RUNTIME_TEXT.values(), HOSTILE_STOP_CLAUSE):
        assert value != value.strip()
        assert value != " ".join(value.split())
        assert value != value.casefold()
        assert "  " in value
        assert "\t" in value
        assert "\n" in value

    constructed_v2 = _runtime_v2_profile()
    projected_v2 = project_v5_runtime_authority_to_v2(derived_v5)
    stages = (
        constructed_v2.to_dict(),
        historical_payload_document["mission_profile"],
        historical_payload.mission_profile.to_dict(),
        derived_v5.to_dict(),
        projected_v2.to_dict(),
    )
    for stage in stages:
        _assert_hostile_runtime_text_mapping(stage)

    for serialized in (
        canonical_bytes(historical_payload_document),
        canonical_bytes(historical_payload.to_dict()),
        canonical_bytes(derived_v5.to_dict()),
        canonical_bytes(projected_v2.to_dict()),
    ):
        for field, expected in HOSTILE_RUNTIME_TEXT.items():
            assert canonical_bytes({field: expected})[1:-1] in serialized
        assert (
            canonical_bytes({"stop_clause": HOSTILE_STOP_CLAUSE})[1:-1]
            in serialized
        )


def test_valid_derivation_produces_exact_canonical_v5(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    assert derived_v5.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert derived_v5.is_launchable_runtime_profile is False
    projected = project_v5_runtime_authority_to_v2(derived_v5)
    embedded = historical_payload.mission_profile
    assert canonical_bytes(projected.to_dict()) == canonical_bytes(embedded.to_dict())
    assert projected.profile_fingerprint == embedded.profile_fingerprint
    assert derived_v5.claim_authority.authorship is ClaimAuthorship.OWNER_AUTHORED
    assert (
        derived_v5.claim_authority.coverage_status
        is ClaimSetCoverageStatus.NOT_ASSESSED
    )
    assert (
        derived_v5.claim_verification_plan_authority.authorship
        is VerificationPlanAuthorship.OWNER_AUTHORED
    )
    assert (
        derived_v5.claim_verification_plan_authority.coverage_status
        is VerificationPlanCoverageStatus.NOT_ASSESSED
    )
    assert (
        derived_v5.verification_evidence_binding_authority.authorship
        is VerificationEvidenceBindingAuthorship.OWNER_AUTHORED
    )
    assert (
        derived_v5.verification_evidence_binding_authority.coverage_status
        is VerificationEvidenceBindingCoverageStatus.NOT_ASSESSED
    )
    assert tuple(
        claim.claim_id for claim in derived_v5.claim_authority.claims
    ) == ("claim.zulu", "claim.alpha", "claim.mike")
    assert tuple(
        item.obligation_id
        for item in derived_v5.claim_verification_plan_authority.verification_obligations
    ) == ("verify.zulu", "verify.echo", "verify.alpha", "verify.human")
    assert tuple(
        item.binding_id
        for item in derived_v5.verification_evidence_binding_authority.bindings
    ) == ("binding.zulu", "binding.alpha", "binding.echo")


def test_derived_v5_equals_the_accepted_canonical_v5_construction(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    embedded = historical_payload.mission_profile
    values = dict(embedded.__dict__)
    values.pop("schema_version")
    values.pop("profile_fingerprint")
    expected = create_native_mission_profile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V5,
        **{
            **values,
            "claim_authority": ClaimAuthority.from_dict(
                {
                    "authorship": ClaimAuthorship.OWNER_AUTHORED.value,
                    "coverage_status": ClaimSetCoverageStatus.NOT_ASSESSED.value,
                    "claims": _owner_claims(),
                }
            ),
            "claim_verification_plan_authority": ClaimVerificationPlanAuthority.from_dict(
                {
                    "authorship": VerificationPlanAuthorship.OWNER_AUTHORED.value,
                    "coverage_status": VerificationPlanCoverageStatus.NOT_ASSESSED.value,
                    "verification_obligations": _owner_plan(),
                }
            ),
            "verification_evidence_binding_authority": VerificationEvidenceBindingAuthority.from_dict(
                {
                    "authorship": VerificationEvidenceBindingAuthorship.OWNER_AUTHORED.value,
                    "coverage_status": (
                        VerificationEvidenceBindingCoverageStatus.NOT_ASSESSED.value
                    ),
                    "bindings": _owner_bindings(
                        embedded.verification.verifier_source_sha256
                    ),
                }
            ),
        },
    )
    assert canonical_bytes(derived_v5.to_dict()) == canonical_bytes(expected.to_dict())
    assert derived_v5.profile_fingerprint == expected.profile_fingerprint


def _ordered_evaluation_members(
    profile: NativeMissionProfile,
) -> tuple[list[dict], list[dict], list[dict]]:
    data = profile.to_dict()
    return (
        data["claim_authority"]["claims"],
        data["claim_verification_plan_authority"]["verification_obligations"],
        data["verification_evidence_binding_authority"]["bindings"],
    )


def test_owner_authored_v5_project_payload_rederive_is_an_exact_reverse_law(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    original = derived_v5
    assert original.claim_authority.authorship is ClaimAuthorship.OWNER_AUTHORED
    assert (
        original.claim_authority.coverage_status
        is ClaimSetCoverageStatus.NOT_ASSESSED
    )
    assert (
        original.claim_verification_plan_authority.authorship
        is VerificationPlanAuthorship.OWNER_AUTHORED
    )
    assert (
        original.claim_verification_plan_authority.coverage_status
        is VerificationPlanCoverageStatus.NOT_ASSESSED
    )
    assert (
        original.verification_evidence_binding_authority.authorship
        is VerificationEvidenceBindingAuthorship.OWNER_AUTHORED
    )
    assert (
        original.verification_evidence_binding_authority.coverage_status
        is VerificationEvidenceBindingCoverageStatus.NOT_ASSESSED
    )

    projected = project_v5_runtime_authority_to_v2(original)
    reverse_payload = _payload_for_runtime_profile(historical_payload, projected)
    assert reverse_payload.validated_historical_structure() is reverse_payload
    assert canonical_bytes(reverse_payload.mission_profile.to_dict()) == canonical_bytes(
        projected.to_dict()
    )

    claims, plan, bindings = _ordered_evaluation_members(original)
    rederived = derive_historical_v5_evaluation_profile(
        target_authorization_payload=reverse_payload,
        result_claims=claims,
        claim_verification_plan=plan,
        verification_evidence_bindings=bindings,
    )
    assert canonical_bytes(rederived.to_dict()) == canonical_bytes(original.to_dict())
    assert rederived.profile_fingerprint == original.profile_fingerprint

    original_members = _ordered_evaluation_members(original)
    rederived_members = _ordered_evaluation_members(rederived)
    assert rederived_members == original_members
    assert tuple(item["claim_id"] for item in rederived_members[0]) == tuple(
        item["claim_id"] for item in original_members[0]
    )
    assert tuple(item["obligation_id"] for item in rederived_members[1]) == tuple(
        item["obligation_id"] for item in original_members[1]
    )
    assert tuple(item["binding_id"] for item in rederived_members[2]) == tuple(
        item["binding_id"] for item in original_members[2]
    )


def test_template_authored_v5_is_reclassified_but_runtime_projection_is_identical(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    template_data = derived_v5.to_dict()
    template_data["claim_authority"]["authorship"] = (
        ClaimAuthorship.TEMPLATE_AUTHORED.value
    )
    template_data["claim_verification_plan_authority"]["authorship"] = (
        VerificationPlanAuthorship.TEMPLATE_AUTHORED.value
    )
    template_data["verification_evidence_binding_authority"]["authorship"] = (
        VerificationEvidenceBindingAuthorship.TEMPLATE_AUTHORED.value
    )
    template = NativeMissionProfile.from_dict(
        _refingerprint_profile(template_data)
    )
    assert template.claim_authority.authorship is ClaimAuthorship.TEMPLATE_AUTHORED
    assert (
        template.claim_verification_plan_authority.authorship
        is VerificationPlanAuthorship.TEMPLATE_AUTHORED
    )
    assert (
        template.verification_evidence_binding_authority.authorship
        is VerificationEvidenceBindingAuthorship.TEMPLATE_AUTHORED
    )

    projected = project_v5_runtime_authority_to_v2(template)
    reverse_payload = _payload_for_runtime_profile(historical_payload, projected)
    claims, plan, bindings = _ordered_evaluation_members(template)
    rederived = derive_historical_v5_evaluation_profile(
        target_authorization_payload=reverse_payload,
        result_claims=claims,
        claim_verification_plan=plan,
        verification_evidence_bindings=bindings,
    )
    assert rederived.claim_authority.authorship is ClaimAuthorship.OWNER_AUTHORED
    assert (
        rederived.claim_verification_plan_authority.authorship
        is VerificationPlanAuthorship.OWNER_AUTHORED
    )
    assert (
        rederived.verification_evidence_binding_authority.authorship
        is VerificationEvidenceBindingAuthorship.OWNER_AUTHORED
    )
    assert canonical_bytes(rederived.to_dict()) != canonical_bytes(template.to_dict())
    assert rederived.profile_fingerprint != template.profile_fingerprint
    assert canonical_bytes(
        project_v5_runtime_authority_to_v2(rederived).to_dict()
    ) == canonical_bytes(projected.to_dict())


def test_derivation_signature_is_exactly_the_four_keyword_only_inputs():
    parameters = inspect.signature(derive_historical_v5_evaluation_profile).parameters
    assert list(parameters) == [
        "target_authorization_payload",
        "result_claims",
        "claim_verification_plan",
        "verification_evidence_bindings",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in parameters.values()
    )


# ---------------------------------------------------------------------------
# Input presence.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["result_claims", "claim_verification_plan", "verification_evidence_bindings"],
)
def test_each_missing_evaluation_layer_is_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    field: str,
):
    kwargs = dict(
        target_authorization_payload=historical_payload,
        result_claims=_owner_claims(),
        claim_verification_plan=_owner_plan(),
        verification_evidence_bindings=_owner_bindings(
            historical_payload.mission_profile.verification.verifier_source_sha256
        ),
    )
    kwargs.pop(field)
    with pytest.raises(TypeError):
        derive_historical_v5_evaluation_profile(**kwargs)


@pytest.mark.parametrize(
    "field,label",
    [
        ("result_claims", "result claims"),
        ("claim_verification_plan", "claim verification plan"),
        ("verification_evidence_bindings", "verification evidence bindings"),
    ],
)
def test_null_empty_and_non_array_evaluation_layers_are_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    field: str,
    label: str,
):
    with pytest.raises(ValueError, match=f"{label} must not be null"):
        _derive(historical_payload, **{field: None})
    with pytest.raises(ValueError, match=f"{label} must be non-empty"):
        _derive(historical_payload, **{field: []})
    for non_array in ("owner text", 17, True, {"claims"}, (1, 2)):
        with pytest.raises(ValueError, match=f"{label} must be an ordered array"):
            _derive(historical_payload, **{field: non_array})


@pytest.mark.parametrize(
    "field,wrapper_key",
    [
        ("result_claims", "claims"),
        ("claim_verification_plan", "verification_obligations"),
        ("verification_evidence_bindings", "bindings"),
    ],
)
def test_authority_wrapper_objects_cannot_smuggle_system_owned_fields(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    field: str,
    wrapper_key: str,
):
    wrapper = {
        "authorship": "TEMPLATE_AUTHORED",
        "coverage_status": "NOT_ASSESSED",
        wrapper_key: [{"anything": True}],
    }
    with pytest.raises(ValueError, match="not an authority object"):
        _derive(historical_payload, **{field: wrapper})


@pytest.mark.parametrize(
    "field,malformed",
    [
        ("result_claims", [17]),
        ("result_claims", [{"claim_id": "claim.only"}]),
        (
            "result_claims",
            [
                {
                    "claim_id": "claim.smuggled",
                    "statement": "A smuggled wrapper field.",
                    "obligation_level": "MANDATORY",
                    "depends_on": [],
                    "non_claims": [],
                    "authorship": "TEMPLATE_AUTHORED",
                }
            ],
        ),
        ("claim_verification_plan", ["not-an-obligation"]),
        ("claim_verification_plan", [{"obligation_id": "verify.only"}]),
        ("verification_evidence_bindings", [None]),
        ("verification_evidence_bindings", [{"binding_id": "binding.only"}]),
        (
            "verification_evidence_bindings",
            [
                {
                    "binding_id": "binding.smuggled",
                    "obligation_id": "verify.zulu",
                    "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
                    "source_authority_reference": "checkpoint.alpha",
                    "coverage_status": "NOT_ASSESSED",
                }
            ],
        ),
    ],
)
def test_malformed_evaluation_members_are_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    field: str,
    malformed: list,
):
    with pytest.raises(ValueError):
        _derive(historical_payload, **{field: malformed})


def test_derivation_produces_v5_only_never_a_lower_schema(
    derived_v5: NativeMissionProfile,
):
    assert derived_v5.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    data = derived_v5.to_dict()
    for key in (
        "claim_authority",
        "claim_verification_plan_authority",
        "verification_evidence_binding_authority",
    ):
        assert key in data


# ---------------------------------------------------------------------------
# Target payload requirement.
# ---------------------------------------------------------------------------


def test_non_payload_targets_are_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    for target in (None, historical_payload.to_dict(), "payload", 41):
        with pytest.raises(ValueError, match="canonical historical v4 payload"):
            _derive_with_target(historical_payload, target)


def _derive_with_target(historical_payload, target):
    return derive_historical_v5_evaluation_profile(
        target_authorization_payload=target,
        result_claims=_owner_claims(),
        claim_verification_plan=_owner_plan(),
        verification_evidence_bindings=_owner_bindings(
            historical_payload.mission_profile.verification.verifier_source_sha256
        ),
    )


def test_invalid_payload_fingerprint_is_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    stale = replace(historical_payload, payload_fingerprint="0" * 64)
    with pytest.raises(ValueError, match="payload fingerprint mismatch"):
        _derive_with_target(historical_payload, stale)


@pytest.mark.parametrize(
    "embedded_factory",
    [
        lambda: FLAGSHIP_INCIDENT_REPLAY_PROFILE,
        _v3_profile,
        _v4_profile,
        _evaluation_profile,
    ],
    ids=["v1", "v3", "v4", "v5"],
)
def test_every_non_v2_embedded_profile_fails_closed(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    embedded_factory,
):
    tampered = replace(historical_payload, mission_profile=embedded_factory())
    with pytest.raises(ValueError, match="runtime-v2"):
        _derive_with_target(historical_payload, tampered)


def test_derivation_uses_structural_not_live_payload_validation(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    reached = AssertionError("live source-directory validation reached")
    with mock.patch(
        "admissible.delegated_gate.native_canary._safe_directory",
        side_effect=reached,
    ):
        again = _derive(historical_payload)
    assert canonical_bytes(again.to_dict()) == canonical_bytes(derived_v5.to_dict())


# ---------------------------------------------------------------------------
# Canonical cross-validation through the delegated laws.
# ---------------------------------------------------------------------------


def _claims_variant(mutate) -> list[dict]:
    claims = _owner_claims()
    mutate(claims)
    return claims


def _plan_variant(mutate) -> list[dict]:
    plan = _owner_plan()
    mutate(plan)
    return plan


def test_invalid_claim_dependencies_are_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    def _unknown(claims):
        claims[0]["depends_on"] = ["claim.ghost"]

    with pytest.raises(ValueError, match="dependency target is missing"):
        _derive(historical_payload, result_claims=_claims_variant(_unknown))

    def _cycle(claims):
        claims[0]["depends_on"] = ["claim.alpha"]

    with pytest.raises(ValueError, match="acyclic"):
        _derive(historical_payload, result_claims=_claims_variant(_cycle))


def test_obligation_referencing_unknown_claim_is_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    def _unknown(plan):
        plan[0]["claim_ids"] = ["claim.ghost"]

    with pytest.raises(ValueError, match="missing from claim authority"):
        _derive(historical_payload, claim_verification_plan=_plan_variant(_unknown))


def test_incompatible_strategy_predicate_pair_is_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    def _mismatch(plan):
        plan[0]["acceptance_predicate"] = "HUMAN_RUBRIC_PASS"

    with pytest.raises(ValueError, match="incompatible"):
        _derive(historical_payload, claim_verification_plan=_plan_variant(_mismatch))


def test_oracle_disclosure_with_information_independence_is_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    def _contradiction(plan):
        plan[0]["oracle_disclosed_to_subject"] = True
        plan[0]["independence_requirements"] = _independence(information=True)

    with pytest.raises(ValueError, match="incompatible"):
        _derive(
            historical_payload,
            claim_verification_plan=_plan_variant(_contradiction),
        )


def _bindings_for(payload, mutate) -> list[dict]:
    bindings = _owner_bindings(
        payload.mission_profile.verification.verifier_source_sha256
    )
    mutate(bindings)
    return bindings


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda bindings: bindings.__setitem__(
                0, {**bindings[0], "binding_id": bindings[2]["binding_id"]}
            ),
            "binding identities must be unique",
        ),
        (
            lambda bindings: bindings.__setitem__(
                2, {**bindings[2], "obligation_id": "verify.zulu"}
            ),
            "obligation identities must be unique",
        ),
        (
            lambda bindings: bindings.__setitem__(
                0, {**bindings[0], "obligation_id": "verify.ghost"}
            ),
            "obligation reference is missing",
        ),
        (
            lambda bindings: bindings.__setitem__(
                0,
                {
                    **bindings[0],
                    "source_authority_type": "FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY",
                    "source_authority_reference": "a" * 64,
                },
            ),
            "incompatible with obligation strategy",
        ),
        (
            lambda bindings: bindings.__setitem__(
                0, {**bindings[0], "source_authority_reference": "checkpoint.missing"}
            ),
            "missing from profile",
        ),
        (
            lambda bindings: bindings.__setitem__(
                1,
                {
                    **bindings[1],
                    "source_authority_reference": hashlib.sha256(
                        b"a foreign verifier"
                    ).hexdigest(),
                },
            ),
            "contradicts profile verification authority",
        ),
        (
            lambda bindings: bindings.append(
                {
                    "binding_id": "binding.human",
                    "obligation_id": "verify.human",
                    "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
                    "source_authority_reference": "checkpoint.zeta",
                }
            ),
            "human-rubric",
        ),
    ],
    ids=[
        "duplicate-binding-ids",
        "duplicate-bound-obligations",
        "unknown-obligation",
        "incompatible-source-type",
        "unknown-checkpoint-command",
        "foreign-behavioral-digest",
        "human-rubric-binding",
    ],
)
def test_binding_cross_reference_violations_are_rejected(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    mutate,
    match: str,
):
    with pytest.raises(ValueError, match=match):
        _derive(
            historical_payload,
            verification_evidence_bindings=_bindings_for(historical_payload, mutate),
        )


def test_procedure_reference_cannot_authorize_a_source(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    # verify.zulu's procedure_reference is the real command checkpoint.zeta;
    # an unavailable binding reference must still fail closed rather than be
    # rescued by the obligation's procedure reference.
    def _unavailable(bindings):
        bindings[0] = {
            **bindings[0],
            "source_authority_reference": "checkpoint.missing",
        }

    plan = _owner_plan()
    assert plan[0]["procedure_reference"] == "checkpoint.zeta"
    assert any(
        command.command_id == "checkpoint.zeta"
        for command in historical_payload.mission_profile.checkpoint_commands
    )
    with pytest.raises(ValueError, match="missing from profile"):
        _derive(
            historical_payload,
            claim_verification_plan=plan,
            verification_evidence_bindings=_bindings_for(
                historical_payload, _unavailable
            ),
        )


def test_non_first_checkpoint_command_is_bound_by_exact_identity(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    command_ids = tuple(
        command.command_id for command in derived_v5.checkpoint_commands
    )
    assert command_ids == ("checkpoint.zeta", "checkpoint.alpha")
    binding = derived_v5.verification_evidence_binding_authority.bindings[0]
    assert binding.source_authority_reference == "checkpoint.alpha"
    assert binding.source_authority_reference == command_ids[1]


def test_non_frozen_behavioral_authority_rejects_behavioral_binding(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    observed = historical_payload.mission_profile.to_dict()
    observed["verification"] = {
        "mode": "OBSERVED_ONLY",
        "verifier_source": None,
        "verifier_source_sha256": None,
        "verifier_timeout_seconds": None,
        "verifier_output_limit_bytes": None,
        "disclose_complete_source": False,
    }
    observed_profile = NativeMissionProfile.from_dict(_refingerprint_profile(observed))
    observed_payload = _payload_for_runtime_profile(
        historical_payload, observed_profile
    )
    behavioral_digest = (
        historical_payload.mission_profile.verification.verifier_source_sha256
    )
    with pytest.raises(ValueError, match="requires frozen behavioral"):
        _derive(
            observed_payload,
            verification_evidence_bindings=[
                {
                    "binding_id": "binding.alpha",
                    "obligation_id": "verify.alpha",
                    "source_authority_type": "FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY",
                    "source_authority_reference": behavioral_digest,
                }
            ],
        )
    checkpoint_only = _derive(
        observed_payload,
        verification_evidence_bindings=[
            {
                "binding_id": "binding.zulu",
                "obligation_id": "verify.zulu",
                "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
                "source_authority_reference": "checkpoint.alpha",
            }
        ],
    )
    assert checkpoint_only.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5


def test_partial_coverage_and_shared_sources_are_valid(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    bound = {
        binding.obligation_id
        for binding in derived_v5.verification_evidence_binding_authority.bindings
    }
    declared = {
        item.obligation_id
        for item in derived_v5.claim_verification_plan_authority.verification_obligations
    }
    assert bound < declared
    assert "verify.human" in declared - bound

    def _shared(bindings):
        bindings[0] = {
            **bindings[0],
            "source_authority_reference": "checkpoint.zeta",
        }

    shared = _derive(
        historical_payload,
        verification_evidence_bindings=_bindings_for(historical_payload, _shared),
    )
    references = [
        binding.source_authority_reference
        for binding in shared.verification_evidence_binding_authority.bindings
        if binding.source_authority_reference == "checkpoint.zeta"
    ]
    assert len(references) == 2


def test_binding_bound_at_256_and_rejected_at_257(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    assert MAX_VERIFICATION_EVIDENCE_BINDINGS == 256
    claims = [
        {
            "claim_id": "claim.bulk",
            "statement": "The bulk behavior exists in the recorded material.",
            "obligation_level": "MANDATORY",
            "depends_on": [],
            "non_claims": [],
        }
    ]
    plan = [
        _obligation_member(
            f"verify.bulk-{index:03d}", ["claim.bulk"],
            "CHECKPOINT_COMMAND", "procedure.bulk", "EXIT_CODE_ZERO",
        )
        for index in range(256)
    ]
    bindings = [
        {
            "binding_id": f"binding.bulk-{index:03d}",
            "obligation_id": f"verify.bulk-{index:03d}",
            "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
            "source_authority_reference": "checkpoint.zeta",
        }
        for index in range(256)
    ]
    derived = _derive(
        historical_payload,
        result_claims=claims,
        claim_verification_plan=plan,
        verification_evidence_bindings=bindings,
    )
    assert len(derived.verification_evidence_binding_authority.bindings) == 256
    overflow = bindings + [
        {
            "binding_id": "binding.bulk-256",
            "obligation_id": "verify.bulk-256",
            "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
            "source_authority_reference": "checkpoint.zeta",
        }
    ]
    with pytest.raises(ValueError, match="cannot exceed 256"):
        _derive(
            historical_payload,
            result_claims=claims,
            claim_verification_plan=plan,
            verification_evidence_bindings=overflow,
        )


# ---------------------------------------------------------------------------
# Exact runtime-authority copying.
# ---------------------------------------------------------------------------


RUNTIME_AUTHORITY_FIELDS = (
    "profile_id",
    "run_id",
    "session_id",
    "gate_id",
    "mission_id",
    "mission_text",
    "gate_objective",
    "gate_clauses",
    "required_evidence_kinds",
    "checkpoint_commands",
    "completion_conditions_text",
    "required_commit_message",
    "required_material_paths",
    "verifier_source",
    "verifier_source_sha256",
    "verifier_timeout_seconds",
    "verifier_output_limit_bytes",
    "budgets",
    "timeout_seconds",
    "stdout_byte_limit",
    "stderr_byte_limit",
    "model",
    "fixture_id",
    "fixture_version",
    "fixture_initial_commit_message",
    "workspace_source",
    "git_end_state_policy",
    "verification",
    "runtime_prompt",
)


@pytest.mark.parametrize("field", RUNTIME_AUTHORITY_FIELDS)
def test_every_runtime_authority_field_is_copied_exactly(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
    field: str,
):
    assert getattr(derived_v5, field) == getattr(
        historical_payload.mission_profile, field
    )


def test_runtime_identities_and_order_observable_collections_are_retained(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    embedded = historical_payload.mission_profile
    assert derived_v5.profile_id == embedded.profile_id
    assert derived_v5.run_id == embedded.run_id
    assert derived_v5.session_id == embedded.session_id
    assert derived_v5.gate_id == embedded.gate_id
    assert derived_v5.mission_id == embedded.mission_id
    # Non-alphabetical owner order must survive exactly.
    assert tuple(clause[0] for clause in derived_v5.gate_clauses) == (
        "clause.zulu",
        "clause.alpha",
    )
    assert tuple(
        command.command_id for command in derived_v5.checkpoint_commands
    ) == ("checkpoint.zeta", "checkpoint.alpha")
    assert derived_v5.checkpoint_commands[0].argv == (
        "node",
        "scripts/zeta-check.js",
        "--strict",
    )
    assert derived_v5.checkpoint_commands[0].timeout_seconds == 45
    assert derived_v5.checkpoint_commands[0].max_capture_bytes == 4096
    assert derived_v5.checkpoint_commands[1].argv == ("python", "-m", "alpha_checks")


@pytest.mark.parametrize(
    "mutation,match",
    [
        ("profile_id", "does not exactly match"),
        # Renaming a bound command or refreezing the verifier breaks the V5
        # binding cross-references before compatibility is even consulted.
        ("command_id", "missing from profile"),
        ("command_argv", "does not exactly match"),
        ("checkpoint_timeout", "does not exactly match"),
        ("checkpoint_capture_limit", "does not exactly match"),
        ("verifier_digest", "contradicts profile verification authority"),
        ("verifier_timeout", "does not exactly match"),
        ("workspace_source", "does not exactly match"),
        ("git_end_state_policy", "does not exactly match"),
        ("runtime_prompt", "does not exactly match"),
        ("material_paths", "does not exactly match"),
        ("model", "does not exactly match"),
        ("mission_text", "does not exactly match"),
        ("gate_clause", "does not exactly match"),
        ("run_id", "does not exactly match"),
        ("session_id", "does not exactly match"),
        ("gate_id", "does not exactly match"),
        ("mission_id", "does not exactly match"),
        ("global_timeout", "does not exactly match"),
        ("stdout_limit", "does not exactly match"),
        ("stderr_limit", "does not exactly match"),
        ("completion_conditions", "does not exactly match"),
    ],
)
def test_any_post_derivation_runtime_mutation_fails_compatibility(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
    mutation: str,
    match: str,
):
    with pytest.raises(ValueError, match=match):
        mutated = _runtime_profile_variant(derived_v5, mutation)
        require_exact_v5_v2_runtime_authority_compatibility(
            evaluation_profile=mutated,
            target_authorization_payload=historical_payload,
        )


def test_projection_postcondition_is_load_bearing(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    with (
        mock.patch(
            "admissible.delegated_gate.historical_evaluation.canonical_bytes",
            side_effect=(b"projected", b"target"),
        ),
        pytest.raises(ValueError, match="does not exactly match"),
    ):
        _derive(historical_payload)


# ---------------------------------------------------------------------------
# Payload separation.
# ---------------------------------------------------------------------------


def _nested_mapping_keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(
            *(_nested_mapping_keys(item) for item in value.values())
        )
    if isinstance(value, (list, tuple)):
        return set().union(*(_nested_mapping_keys(item) for item in value))
    return set()


def _nested_scalar_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _nested_scalar_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _nested_scalar_values(item)
    else:
        yield value


def test_distinct_payload_targets_are_separate_from_equal_derived_v5_identity(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    changed = historical_payload.to_dict()
    changed["source_head"] = (
        "f" * len(changed["source_head"])
        if changed["source_head"] != "f" * len(changed["source_head"])
        else "e" * len(changed["source_head"])
    )
    initialized = changed["initialized_workspace"]
    initialized["initial_git_head"] = (
        "d" * len(initialized["initial_git_head"])
        if initialized["initial_git_head"]
        != "d" * len(initialized["initial_git_head"])
        else "c" * len(initialized["initial_git_head"])
    )
    initialized["initial_material_tree_hash"] = (
        "b" * 64
        if initialized["initial_material_tree_hash"] != "b" * 64
        else "a" * 64
    )
    other_payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(changed)
    )
    assert historical_payload.validated_historical_structure() is historical_payload
    assert other_payload.validated_historical_structure() is other_payload
    assert other_payload.source_head != historical_payload.source_head
    assert (
        other_payload.initialized_workspace.initial_git_head
        != historical_payload.initialized_workspace.initial_git_head
    )
    assert (
        other_payload.initialized_workspace.initial_material_tree_hash
        != historical_payload.initialized_workspace.initial_material_tree_hash
    )
    assert (
        other_payload.mission_profile.profile_fingerprint
        == historical_payload.mission_profile.profile_fingerprint
    )
    assert canonical_bytes(other_payload.mission_profile.to_dict()) == canonical_bytes(
        historical_payload.mission_profile.to_dict()
    )
    assert other_payload.payload_fingerprint != historical_payload.payload_fingerprint

    pairing_side_effect = AssertionError(
        "derivation attempted to create a pairing authority"
    )
    with mock.patch(
        "admissible.delegated_gate.historical_evaluation."
        "create_historical_evaluation_pairing_authority",
        side_effect=pairing_side_effect,
    ) as pairing_factory:
        derived_a = _derive(historical_payload)
        derived_b = _derive(other_payload)
    pairing_factory.assert_not_called()

    assert canonical_bytes(derived_a.to_dict()) == canonical_bytes(derived_v5.to_dict())
    assert canonical_bytes(derived_b.to_dict()) == canonical_bytes(derived_a.to_dict())
    assert derived_b.profile_fingerprint == derived_a.profile_fingerprint

    v5_mapping = derived_a.to_dict()
    v5_bytes = canonical_bytes(v5_mapping)
    v5_values = tuple(_nested_scalar_values(v5_mapping))
    for payload_fingerprint in (
        historical_payload.payload_fingerprint,
        other_payload.payload_fingerprint,
    ):
        assert payload_fingerprint not in v5_values
        assert payload_fingerprint.encode("ascii") not in v5_bytes

    payload_mapping = historical_payload.to_dict()
    runtime_mapping_keys = _nested_mapping_keys(
        payload_mapping["mission_profile"]
    )
    outer_payload_only_fields = set(payload_mapping) - runtime_mapping_keys
    outer_payload_only_fields.update(
        set(payload_mapping["initialized_workspace"]) - runtime_mapping_keys
    )
    assert outer_payload_only_fields.isdisjoint(_nested_mapping_keys(v5_mapping))

    pairing_a = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=derived_a,
        target_authorization_payload=historical_payload,
    )
    pairing_b = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=derived_b,
        target_authorization_payload=other_payload,
    )
    assert (
        pairing_a.target_authorization_payload_fingerprint
        == historical_payload.payload_fingerprint
    )
    assert (
        pairing_b.target_authorization_payload_fingerprint
        == other_payload.payload_fingerprint
    )
    assert (
        pairing_a.evaluation_profile_fingerprint
        == pairing_b.evaluation_profile_fingerprint
        == derived_a.profile_fingerprint
    )
    assert pairing_a.authority_fingerprint != pairing_b.authority_fingerprint
    for pairing in (pairing_a, pairing_b):
        assert pairing.authority_fingerprint not in v5_values
        assert pairing.authority_fingerprint.encode("ascii") not in v5_bytes


def test_derived_v5_carries_no_pairing_or_execution_fields(
    derived_v5: NativeMissionProfile,
):
    data = derived_v5.to_dict()
    forbidden = {
        "target_authorization_payload_fingerprint",
        "actor_id",
        "authority_fingerprint",
        "evaluation_profile_fingerprint",
        "request_fingerprint",
        "evidence",
        "resolution_status",
        "retrieval_status",
        "obligation_result",
        "claim_result",
        "owner_disposition",
        "product_verdict",
        "compatibility_result",
    }
    assert forbidden.isdisjoint(data)
    with pytest.raises(ValueError, match="keys"):
        HistoricalEvaluationPairingAuthority.from_dict(data)


def test_derivation_creates_no_pairing_authority_side_effect(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    forbidden = AssertionError("derivation attempted to create a pairing authority")
    with (
        mock.patch(
            "admissible.delegated_gate.historical_evaluation."
            "create_historical_evaluation_pairing_authority",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.historical_evaluation."
            "HistoricalEvaluationPairingAuthority",
            side_effect=forbidden,
        ),
    ):
        derived = _derive(historical_payload)
    assert canonical_bytes(derived.to_dict()) == canonical_bytes(derived_v5.to_dict())


# ---------------------------------------------------------------------------
# Inertness.
# ---------------------------------------------------------------------------


def test_derivation_never_accesses_filesystem_git_stores_or_product_surfaces(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    derived_v5: NativeMissionProfile,
):
    forbidden = AssertionError("inert derivation accessed a forbidden dependency")
    dependencies = (
        mock.patch(
            "admissible.delegated_gate.native_canary._safe_directory",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary._run",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.subprocess.run",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.subprocess.Popen",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.subprocess.check_output",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.preflight_native_cursor",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.AtomicNativeExecutionStore",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.AtomicDelegatedSessionStore",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.capture_checkpoint",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.run_behavioral_verifier",
            side_effect=forbidden,
        ),
        mock.patch(
            "admissible.delegated_gate.native_canary.reconstruct_completed_native_mission",
            side_effect=forbidden,
        ),
        mock.patch.object(Path, "read_bytes", side_effect=forbidden),
        mock.patch.object(Path, "read_text", side_effect=forbidden),
        mock.patch.object(Path, "write_bytes", side_effect=forbidden),
        mock.patch.object(Path, "write_text", side_effect=forbidden),
        mock.patch.object(Path, "mkdir", side_effect=forbidden),
        mock.patch.object(Path, "stat", side_effect=forbidden),
        mock.patch.object(Path, "exists", side_effect=forbidden),
        mock.patch("builtins.open", side_effect=forbidden),
        mock.patch.object(io, "open", side_effect=forbidden),
        mock.patch.object(os, "stat", side_effect=forbidden),
        mock.patch.object(os, "lstat", side_effect=forbidden),
        mock.patch.object(os, "listdir", side_effect=forbidden),
        mock.patch.object(os, "scandir", side_effect=forbidden),
    )
    product_prefixes = (
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.product_launcher",
        "admissible.delegated_gate.native_acceptance",
    )
    product_modules_before = {
        name for name in sys.modules if name.startswith(product_prefixes)
    }
    with ExitStack() as stack:
        for dependency in dependencies:
            stack.enter_context(dependency)
        derived = _derive(historical_payload)
    product_modules_after = {
        name for name in sys.modules if name.startswith(product_prefixes)
    }
    assert product_modules_after == product_modules_before
    assert canonical_bytes(derived.to_dict()) == canonical_bytes(derived_v5.to_dict())


def test_error_paths_are_bounded_and_leak_free(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    tmp_path: Path,
):
    failing_calls = (
        lambda: _derive(historical_payload, result_claims=None),
        lambda: _derive(historical_payload, result_claims=[]),
        lambda: _derive(historical_payload, result_claims=[{"claim_id": "x"}]),
        lambda: _derive(historical_payload, claim_verification_plan=[17]),
        lambda: _derive(historical_payload, verification_evidence_bindings=[None]),
        lambda: _derive_with_target(historical_payload, None),
        lambda: _derive_with_target(
            historical_payload,
            replace(historical_payload, payload_fingerprint="0" * 64),
        ),
    )
    for call in failing_calls:
        with pytest.raises(ValueError) as excinfo:
            call()
        message = str(excinfo.value)
        assert 0 < len(message) < 300
        assert "Traceback" not in message
        assert "\\" not in message
        assert "/" not in message
        assert "0x" not in message
        assert ".py" not in message
        assert str(tmp_path) not in message
        assert historical_payload.source_repository not in message


# ---------------------------------------------------------------------------
# Existing behavior preservation.
# ---------------------------------------------------------------------------


def test_derivation_preserves_all_existing_canonical_objects_and_refusals(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    tmp_path: Path,
):
    objects = (
        FLAGSHIP_INCIDENT_REPLAY_PROFILE,
        _runtime_v2_profile(),
        _v3_profile(),
        _v4_profile(),
        _v5_profile(),
        _evaluation_profile(),
    )
    before_bytes = tuple(canonical_bytes(item.to_dict()) for item in objects)
    before_fingerprints = tuple(item.profile_fingerprint for item in objects)
    before_launchability = tuple(
        item.is_launchable_runtime_profile for item in objects
    )
    payload_bytes = canonical_bytes(historical_payload.to_dict())
    payload_fingerprint = historical_payload.payload_fingerprint
    derived = _derive(historical_payload)
    assert tuple(canonical_bytes(item.to_dict()) for item in objects) == before_bytes
    assert tuple(item.profile_fingerprint for item in objects) == before_fingerprints
    assert (
        tuple(item.is_launchable_runtime_profile for item in objects)
        == before_launchability
    )
    assert canonical_bytes(historical_payload.to_dict()) == payload_bytes
    assert historical_payload.payload_fingerprint == payload_fingerprint
    assert derived.is_launchable_runtime_profile is False
    assert derived.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert (
        historical_payload.mission_profile.schema_version
        == MISSION_PROFILE_SCHEMA_VERSION_V2
    )
    document = tmp_path / "derived-v5.json"
    document.write_text(canonical_json(derived.to_dict()), encoding="utf-8")
    with pytest.raises(ValueError, match="must use the v2 schema"):
        load_native_mission_profile_document(document)
