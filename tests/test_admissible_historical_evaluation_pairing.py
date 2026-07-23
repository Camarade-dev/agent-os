from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import hashlib
import inspect
from pathlib import Path
import sys
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.historical_evaluation import (
    HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION,
    HistoricalEvaluationPairingAuthority,
    create_historical_evaluation_pairing_authority,
    project_v5_runtime_authority_to_v2,
    require_exact_v5_v2_runtime_authority_compatibility,
    validate_historical_evaluation_pairing_relation,
)
from admissible.delegated_gate.mission_profile import (
    FLAGSHIP_INCIDENT_REPLAY_PROFILE,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
    VerificationAuthority,
    VerificationMode,
    create_native_mission_profile,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    create_canary_session,
    load_historical_native_canary_authorization_payload_v4,
)
from test_admissible_claim_authority_v3 import _profile as _v3_profile
from test_admissible_claim_verification_plan_v4 import _profile as _v4_profile
from test_admissible_verification_evidence_binding_v5 import _profile as _v5_profile
from test_admissible_workflow_recovery_profile import _payload_harness


def _evaluation_profile() -> NativeMissionProfile:
    base = _v5_profile()
    verifier_source = "def verify(workspace):\n    return workspace is not None\n"
    verification = VerificationAuthority(
        mode=VerificationMode.FROZEN_BEHAVIORAL,
        verifier_source=verifier_source,
        verifier_source_sha256=hashlib.sha256(
            verifier_source.encode("utf-8")
        ).hexdigest(),
        verifier_timeout_seconds=30,
        verifier_output_limit_bytes=8192,
        disclose_complete_source=True,
    )
    values = dict(base.__dict__)
    values.pop("schema_version")
    values.pop("profile_fingerprint")
    values.update(
        verification=verification,
        verifier_source=verification.verifier_source,
        verifier_source_sha256=verification.verifier_source_sha256,
        verifier_timeout_seconds=verification.verifier_timeout_seconds,
        verifier_output_limit_bytes=verification.verifier_output_limit_bytes,
    )
    return create_native_mission_profile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V5,
        **values,
    )


@pytest.fixture(scope="module")
def evaluation_profile() -> NativeMissionProfile:
    return _evaluation_profile()


def _refingerprint_profile(data: dict) -> dict:
    data = deepcopy(data)
    data["profile_fingerprint"] = fingerprint(
        {key: value for key, value in data.items() if key != "profile_fingerprint"}
    )
    return data


def _refingerprint_payload(data: dict) -> dict:
    data = deepcopy(data)
    data["payload_fingerprint"] = fingerprint(
        {key: value for key, value in data.items() if key != "payload_fingerprint"}
    )
    return data


@pytest.fixture(scope="module")
def historical_payload_document(
    tmp_path_factory: pytest.TempPathFactory,
    evaluation_profile: NativeMissionProfile,
) -> dict:
    tmp_path = tmp_path_factory.mktemp("historical-evaluation")
    runtime_profile = project_v5_runtime_authority_to_v2(evaluation_profile)
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


def _payload_for_runtime_profile(
    payload: NativeCanaryAuthorizationPayloadV4,
    profile: NativeMissionProfile,
) -> NativeCanaryAuthorizationPayloadV4:
    profile.validated()
    data = payload.to_dict()
    data["mission_profile"] = profile.to_dict()
    data["run_id"] = profile.run_id
    data["session_id"] = profile.session_id
    data["selected_model"] = profile.model
    data["timeout_seconds"] = profile.timeout_seconds
    data["stdout_byte_limit"] = profile.stdout_byte_limit
    data["stderr_byte_limit"] = profile.stderr_byte_limit
    data["budgets"] = list(profile.budgets)
    data["required_commit_message"] = profile.required_commit_message
    source = profile.effective_workspace_source
    if source.fixture_id is not None:
        data["fixture_version"] = f"{source.fixture_id}@v{source.fixture_version}"
    else:
        data["fixture_version"] = f"local-git@{source.identity_fingerprint}"
    data["initialized_workspace"]["source_kind"] = source.kind.value
    data["initialized_workspace"]["source_identity"] = source.identity_fingerprint
    old_root = Path(data["run_root"])
    run_root = old_root.parent / profile.run_id
    data["run_root"] = str(run_root)
    data["workspace_root"] = str(run_root / WORKSPACE_DIRECTORY_NAME)
    data["evidence_root"] = str(run_root / EVIDENCE_DIRECTORY_NAME)
    data["native_sidecar_root"] = str(
        run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME
    )
    derived = create_canary_session(session_id=profile.session_id, profile=profile)
    data["mission_fingerprint"] = derived.mission.mission_fingerprint
    data["gate_plan_fingerprint"] = derived.gate_plan.plan_fingerprint
    data["gate_contract_fingerprint"] = derived.current_gate.contract_fingerprint
    return load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(data)
    )


def _runtime_profile_variant(
    profile: NativeMissionProfile,
    mutation: str,
) -> NativeMissionProfile:
    data = profile.to_dict()
    if mutation == "profile_id":
        data["profile_id"] = "changed-profile"
    elif mutation == "command_id":
        data["checkpoint_commands"][0]["command_id"] = "checkpoint.changed"
    elif mutation == "command_argv":
        data["checkpoint_commands"][0]["argv"].append("--changed")
    elif mutation == "checkpoint_timeout":
        data["checkpoint_commands"][0]["timeout_seconds"] += 1
    elif mutation == "checkpoint_capture_limit":
        data["checkpoint_commands"][0]["max_capture_bytes"] += 1
    elif mutation == "verifier_digest":
        source = data["verification"]["verifier_source"] + "# changed\n"
        data["verification"]["verifier_source"] = source
        data["verification"]["verifier_source_sha256"] = hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()
    elif mutation == "verifier_timeout":
        data["verification"]["verifier_timeout_seconds"] += 1
    elif mutation == "workspace_source":
        data["workspace_source"]["fixture_id"] = "changed-fixture"
        data["workspace_source"]["fixture_version"] = 2
    elif mutation == "git_end_state_policy":
        data["git_end_state_policy"]["final_remotes_absent"] = False
    elif mutation == "runtime_prompt":
        data["runtime_prompt"]["stop_clause"] += " Changed."
    elif mutation == "material_paths":
        data["git_end_state_policy"]["required_material_paths"].append("CHANGED.md")
    elif mutation == "model":
        data["model"] = "changed-model"
    elif mutation == "mission_text":
        data["mission_text"] += "\nChanged mission authority."
    elif mutation == "gate_clause":
        data["gate_clauses"][0][1] += " Changed."
    elif mutation == "run_id":
        data["run_id"] = "changed-run"
    elif mutation == "session_id":
        data["session_id"] = "changed-session"
    elif mutation == "gate_id":
        data["gate_id"] = "changed-gate"
    elif mutation == "mission_id":
        data["mission_id"] = "changed-mission"
    elif mutation == "global_timeout":
        data["timeout_seconds"] += 1
    elif mutation == "stdout_limit":
        data["stdout_byte_limit"] += 1
    elif mutation == "stderr_limit":
        data["stderr_byte_limit"] += 1
    elif mutation == "completion_conditions":
        data["completion_conditions_text"] += " Changed."
    else:
        raise AssertionError(f"unknown test mutation: {mutation}")
    return NativeMissionProfile.from_dict(_refingerprint_profile(data))


def _updated_evaluation_claim(
    profile: NativeMissionProfile,
) -> NativeMissionProfile:
    data = profile.to_dict()
    data["claim_authority"]["claims"][0]["statement"] += " Updated."
    return NativeMissionProfile.from_dict(_refingerprint_profile(data))


def test_historical_loader_accepts_absent_paths_and_is_pure(
    historical_payload_document: dict,
):
    forbidden = AssertionError("historical loader accessed a current resource")
    with (
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
        mock.patch.object(Path, "read_bytes", side_effect=forbidden),
        mock.patch.object(Path, "read_text", side_effect=forbidden),
        mock.patch.object(Path, "stat", side_effect=forbidden),
        mock.patch.object(Path, "exists", side_effect=forbidden),
    ):
        loaded = load_historical_native_canary_authorization_payload_v4(
            historical_payload_document
        )
    assert loaded.payload_fingerprint == historical_payload_document["payload_fingerprint"]
    assert loaded.mission_profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2
    assert loaded.mission_profile.is_launchable_runtime_profile is True


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update(schema_version="not-v4"),
        lambda data: data.update(unknown=True),
        lambda data: data.pop("source_head"),
    ],
    ids=["schema", "unknown-key", "missing-key"],
)
def test_historical_loader_rejects_schema_and_key_mutations(
    historical_payload_document: dict,
    mutation,
):
    data = deepcopy(historical_payload_document)
    mutation(data)
    with pytest.raises(ValueError):
        load_historical_native_canary_authorization_payload_v4(data)


def test_historical_loader_rejects_non_v2_embedded_profile(
    historical_payload_document: dict,
):
    data = deepcopy(historical_payload_document)
    data["mission_profile"] = _v4_profile().to_dict()
    data = _refingerprint_payload(data)
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        load_historical_native_canary_authorization_payload_v4(data)


def test_historical_loader_rejects_payload_and_profile_fingerprint_mismatch(
    historical_payload_document: dict,
):
    stale_payload = deepcopy(historical_payload_document)
    stale_payload["payload_fingerprint"] = "0" * 64
    with pytest.raises(ValueError, match="payload fingerprint mismatch"):
        load_historical_native_canary_authorization_payload_v4(stale_payload)
    stale_profile = deepcopy(historical_payload_document)
    stale_profile["mission_profile"]["profile_fingerprint"] = "0" * 64
    stale_profile = _refingerprint_payload(stale_profile)
    with pytest.raises(ValueError, match="profile fingerprint mismatch"):
        load_historical_native_canary_authorization_payload_v4(stale_profile)


@pytest.mark.parametrize(
    "field",
    [
        "run_id",
        "session_id",
        "selected_model",
        "timeout_seconds",
        "stdout_byte_limit",
        "stderr_byte_limit",
        "budgets",
        "required_commit_message",
        "fixture_version",
    ],
)
def test_historical_loader_rejects_every_mirrored_field_mismatch(
    historical_payload_document: dict,
    field: str,
):
    data = deepcopy(historical_payload_document)
    if field == "budgets":
        data[field] = [0, 1, 0, 0, 0]
    elif isinstance(data[field], int):
        data[field] += 1
    elif data[field] is None:
        data[field] = "changed"
    else:
        data[field] = f"{data[field]}-changed"
    with pytest.raises(ValueError, match="contradicts the embedded mission profile"):
        load_historical_native_canary_authorization_payload_v4(
            _refingerprint_payload(data)
        )


@pytest.mark.parametrize(
    "field",
    ["mission_fingerprint", "gate_plan_fingerprint", "gate_contract_fingerprint"],
)
def test_historical_loader_rejects_derived_mission_gate_fingerprint_mismatch(
    historical_payload_document: dict,
    field: str,
):
    data = deepcopy(historical_payload_document)
    data[field] = "1" * 64
    with pytest.raises(ValueError, match="not derived"):
        load_historical_native_canary_authorization_payload_v4(
            _refingerprint_payload(data)
        )


def test_historical_loader_rejects_initialized_workspace_relation_mismatch(
    historical_payload_document: dict,
):
    data = deepcopy(historical_payload_document)
    data["initialized_workspace"]["source_identity"] = "1" * 64
    with pytest.raises(ValueError, match="source identity contradicts"):
        load_historical_native_canary_authorization_payload_v4(
            _refingerprint_payload(data)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_head", "NOT-A-GIT-OID"),
        ("executable", "relative-agent.exe"),
        ("launcher_prefix", ["relative-launcher.exe"]),
    ],
)
def test_historical_loader_rejects_noncanonical_embedded_source_authority(
    historical_payload_document: dict,
    field: str,
    value,
):
    data = deepcopy(historical_payload_document)
    data[field] = value
    with pytest.raises(ValueError):
        load_historical_native_canary_authorization_payload_v4(
            _refingerprint_payload(data)
        )


def test_live_payload_validation_retains_environmental_check(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    reached = AssertionError("live source-directory validation reached")
    with (
        mock.patch(
            "admissible.delegated_gate.native_canary._safe_directory",
            side_effect=reached,
        ),
        pytest.raises(AssertionError, match="live source-directory"),
    ):
        historical_payload.validated()


def test_v5_projection_is_exact_deterministic_and_order_preserving(
    evaluation_profile: NativeMissionProfile,
):
    before = canonical_bytes(evaluation_profile.to_dict())
    projected = project_v5_runtime_authority_to_v2(evaluation_profile)
    projected_again = project_v5_runtime_authority_to_v2(evaluation_profile)
    expected = evaluation_profile.to_dict()
    expected.pop("claim_authority")
    expected.pop("claim_verification_plan_authority")
    expected.pop("verification_evidence_binding_authority")
    expected["schema_version"] = MISSION_PROFILE_SCHEMA_VERSION_V2
    expected.pop("profile_fingerprint")
    expected["profile_fingerprint"] = fingerprint(expected)
    assert projected.to_dict() == expected
    assert projected.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2
    assert projected.is_launchable_runtime_profile is True
    assert canonical_bytes(projected.to_dict()) == canonical_bytes(projected_again.to_dict())
    assert projected.profile_fingerprint == projected_again.profile_fingerprint
    assert projected.gate_clauses == evaluation_profile.gate_clauses
    assert projected.required_evidence_kinds == evaluation_profile.required_evidence_kinds
    assert projected.checkpoint_commands == evaluation_profile.checkpoint_commands
    assert projected.required_material_paths == evaluation_profile.required_material_paths
    assert canonical_bytes(evaluation_profile.to_dict()) == before


@pytest.mark.parametrize(
    "profile",
    [
        FLAGSHIP_INCIDENT_REPLAY_PROFILE,
        project_v5_runtime_authority_to_v2(_evaluation_profile()),
        _v3_profile(),
        _v4_profile(),
    ],
    ids=["v1", "v2", "v3", "v4"],
)
def test_projection_rejects_every_non_v5_profile(profile: NativeMissionProfile):
    with pytest.raises(ValueError, match="exact v5 schema"):
        project_v5_runtime_authority_to_v2(profile)


def test_projection_rejects_mapping_and_malformed_v5(
    evaluation_profile: NativeMissionProfile,
):
    with pytest.raises(ValueError, match="canonical NativeMissionProfile"):
        project_v5_runtime_authority_to_v2(evaluation_profile.to_dict())  # type: ignore[arg-type]
    malformed = replace(evaluation_profile, profile_fingerprint="0" * 64)
    with pytest.raises(ValueError, match="profile fingerprint mismatch"):
        project_v5_runtime_authority_to_v2(malformed)


def test_exact_compatibility_and_pairing_accept_known_projection(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    projected = require_exact_v5_v2_runtime_authority_compatibility(
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    assert canonical_bytes(projected.to_dict()) == canonical_bytes(
        historical_payload.mission_profile.to_dict()
    )
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    assert authority.actor_id == "owner.primary"


def test_canonical_bytes_are_primary_even_when_profile_fingerprints_match(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    assert (
        project_v5_runtime_authority_to_v2(evaluation_profile).profile_fingerprint
        == historical_payload.mission_profile.profile_fingerprint
    )
    with (
        mock.patch(
            "admissible.delegated_gate.historical_evaluation.canonical_bytes",
            side_effect=(b"projected", b"target"),
        ),
        pytest.raises(ValueError, match="does not exactly match"),
    ):
        require_exact_v5_v2_runtime_authority_compatibility(
            evaluation_profile=evaluation_profile,
            target_authorization_payload=historical_payload,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "profile_id",
        "command_id",
        "command_argv",
        "checkpoint_timeout",
        "checkpoint_capture_limit",
        "verifier_digest",
        "verifier_timeout",
        "workspace_source",
        "git_end_state_policy",
        "runtime_prompt",
        "material_paths",
        "model",
        "mission_text",
        "gate_clause",
        "run_id",
        "session_id",
        "gate_id",
        "mission_id",
        "global_timeout",
        "stdout_limit",
        "stderr_limit",
        "completion_conditions",
    ],
)
def test_every_runtime_authority_difference_rejects_pairing(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    mutation: str,
):
    target = _runtime_profile_variant(
        historical_payload.mission_profile,
        mutation,
    )
    incompatible_payload = _payload_for_runtime_profile(historical_payload, target)
    with pytest.raises(ValueError, match="does not exactly match"):
        create_historical_evaluation_pairing_authority(
            actor_id="owner.primary",
            evaluation_profile=evaluation_profile,
            target_authorization_payload=incompatible_payload,
        )


def test_invalid_budget_difference_still_rejects_pairing(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    malformed_profile = replace(
        historical_payload.mission_profile,
        budgets=(0, 1, 0, 0, 0),
    )
    malformed_payload = replace(
        historical_payload,
        mission_profile=malformed_profile,
        budgets=malformed_profile.budgets,
    )
    with pytest.raises(ValueError, match="exact one-shot budgets"):
        create_historical_evaluation_pairing_authority(
            actor_id="owner.primary",
            evaluation_profile=evaluation_profile,
            target_authorization_payload=malformed_payload,
        )


def test_pairing_serialized_shape_fingerprint_and_mapping_order(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    authority = create_historical_evaluation_pairing_authority(
        actor_id="Owner.MixedCase",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    data = authority.to_dict()
    assert list(data) == [
        "schema_version",
        "actor_id",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "authority_fingerprint",
    ]
    assert data == {
        "schema_version": HISTORICAL_EVALUATION_PAIRING_AUTHORITY_SCHEMA_VERSION,
        "actor_id": "Owner.MixedCase",
        "evaluation_profile_fingerprint": evaluation_profile.profile_fingerprint,
        "target_authorization_payload_fingerprint": historical_payload.payload_fingerprint,
        "authority_fingerprint": authority.authority_fingerprint,
    }
    assert authority.authority_fingerprint == fingerprint(authority._body())
    reversed_mapping = dict(reversed(list(data.items())))
    assert HistoricalEvaluationPairingAuthority.from_dict(reversed_mapping) == authority
    assert canonical_bytes(reversed_mapping) == canonical_bytes(data)


def test_each_pairing_reference_changes_self_fingerprint(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    baseline = authority.authority_fingerprint
    for field, changed in (
        ("actor_id", "owner.changed"),
        ("evaluation_profile_fingerprint", "1" * 64),
        ("target_authorization_payload_fingerprint", "2" * 64),
    ):
        body = authority._body()
        body[field] = changed
        mutated = HistoricalEvaluationPairingAuthority.from_dict(
            {**body, "authority_fingerprint": fingerprint(body)}
        )
        assert mutated.authority_fingerprint != baseline


@pytest.mark.parametrize(
    "forbidden",
    [
        "timestamp",
        "status",
        "path",
        "request_fingerprint",
        "result",
        "evidence",
        "binding_authority_fingerprint",
        "compatible_runtime_profile_fingerprint",
        "compatibility_result",
        "resolution_status",
        "product_contract_id",
        "product_verdict",
    ],
)
def test_pairing_direct_load_rejects_unknown_and_forbidden_fields(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    forbidden: str,
):
    data = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    ).to_dict()
    data[forbidden] = "forbidden"
    with pytest.raises(ValueError, match="keys"):
        HistoricalEvaluationPairingAuthority.from_dict(data)


def test_pairing_direct_load_rejects_actor_digest_and_self_fingerprint_mutations(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    data = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    ).to_dict()
    for field, value, match in (
        ("actor_id", "bad actor", "stable identifier"),
        ("evaluation_profile_fingerprint", "bad", "SHA-256"),
        ("target_authorization_payload_fingerprint", "bad", "SHA-256"),
        ("authority_fingerprint", "0" * 64, "fingerprint mismatch"),
    ):
        mutated = {**data, field: value}
        with pytest.raises(ValueError, match=match):
            HistoricalEvaluationPairingAuthority.from_dict(mutated)


def test_factory_does_not_accept_owner_supplied_fingerprints(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    parameters = inspect.signature(
        create_historical_evaluation_pairing_authority
    ).parameters
    assert set(parameters) == {
        "actor_id",
        "evaluation_profile",
        "target_authorization_payload",
    }
    with pytest.raises(TypeError):
        create_historical_evaluation_pairing_authority(
            actor_id="owner.primary",
            evaluation_profile=evaluation_profile,
            target_authorization_payload=historical_payload,
            evaluation_profile_fingerprint="0" * 64,  # type: ignore[call-arg]
        )


def test_relation_accepts_exact_documents_and_rejects_updated_v5(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    assert validate_historical_evaluation_pairing_relation(
        authority=authority,
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    ) == authority
    with pytest.raises(ValueError, match="does not reference this v5"):
        validate_historical_evaluation_pairing_relation(
            authority=authority,
            evaluation_profile=_updated_evaluation_claim(evaluation_profile),
            target_authorization_payload=historical_payload,
        )


def test_relation_rejects_wrong_v5_and_v4_evaluation_profile(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    changed_runtime = _runtime_profile_variant(
        project_v5_runtime_authority_to_v2(evaluation_profile),
        "mission_text",
    )
    wrong = evaluation_profile.to_dict()
    changed = changed_runtime.to_dict()
    for key in tuple(changed):
        if key not in {"schema_version", "profile_fingerprint"}:
            wrong[key] = changed[key]
    wrong = NativeMissionProfile.from_dict(_refingerprint_profile(wrong))
    with pytest.raises(ValueError, match="does not reference this v5"):
        validate_historical_evaluation_pairing_relation(
            authority=authority,
            evaluation_profile=wrong,
            target_authorization_payload=historical_payload,
        )
    with pytest.raises(ValueError, match="exact v5 schema"):
        validate_historical_evaluation_pairing_relation(
            authority=authority,
            evaluation_profile=_v4_profile(),
            target_authorization_payload=historical_payload,
        )


def test_relation_targets_payload_fingerprint_not_embedded_profile_only(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    changed = historical_payload.to_dict()
    changed["source_head"] = "f" * 40
    other_payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(changed)
    )
    assert (
        other_payload.mission_profile.profile_fingerprint
        == historical_payload.mission_profile.profile_fingerprint
    )
    assert other_payload.payload_fingerprint != historical_payload.payload_fingerprint
    copied = HistoricalEvaluationPairingAuthority.from_dict(authority.to_dict())
    with pytest.raises(ValueError, match="does not reference this v4"):
        validate_historical_evaluation_pairing_relation(
            authority=copied,
            evaluation_profile=evaluation_profile,
            target_authorization_payload=other_payload,
        )


def test_relation_rejects_wrong_payload_with_different_runtime_profile(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    wrong_profile = _runtime_profile_variant(
        historical_payload.mission_profile,
        "command_argv",
    )
    wrong_payload = _payload_for_runtime_profile(historical_payload, wrong_profile)
    with pytest.raises(ValueError, match="does not reference this v4"):
        validate_historical_evaluation_pairing_relation(
            authority=authority,
            evaluation_profile=evaluation_profile,
            target_authorization_payload=wrong_payload,
        )


def test_factory_and_relation_never_access_runtime_evidence_or_product_paths(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    forbidden = AssertionError("inert pairing accessed a forbidden dependency")
    dependencies = (
        mock.patch(
            "admissible.delegated_gate.native_canary._safe_directory",
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
    )
    product_modules_before = {
        name
        for name in sys.modules
        if name.startswith(
            (
                "admissible.product_service",
                "admissible.product_read_model",
                "admissible.delegated_gate.native_acceptance",
            )
        )
    }
    with ExitStack() as stack:
        for dependency in dependencies:
            stack.enter_context(dependency)
        authority = create_historical_evaluation_pairing_authority(
            actor_id="owner.primary",
            evaluation_profile=evaluation_profile,
            target_authorization_payload=historical_payload,
        )
        validate_historical_evaluation_pairing_relation(
            authority=authority,
            evaluation_profile=evaluation_profile,
            target_authorization_payload=historical_payload,
        )
    product_modules_after = {
        name
        for name in sys.modules
        if name.startswith(
            (
                "admissible.product_service",
                "admissible.product_read_model",
                "admissible.delegated_gate.native_acceptance",
            )
        )
    }
    assert product_modules_after == product_modules_before


def test_pairing_is_inert_and_preserves_all_historical_canonical_objects(
    evaluation_profile: NativeMissionProfile,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    objects = (
        FLAGSHIP_INCIDENT_REPLAY_PROFILE,
        project_v5_runtime_authority_to_v2(evaluation_profile),
        _v3_profile(),
        _v4_profile(),
        evaluation_profile,
    )
    before_bytes = tuple(canonical_bytes(item.to_dict()) for item in objects)
    before_fingerprints = tuple(item.profile_fingerprint for item in objects)
    before_launchability = tuple(item.is_launchable_runtime_profile for item in objects)
    payload_bytes = canonical_bytes(historical_payload.to_dict())
    payload_fingerprint = historical_payload.payload_fingerprint
    authority = create_historical_evaluation_pairing_authority(
        actor_id="owner.primary",
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    validate_historical_evaluation_pairing_relation(
        authority=authority,
        evaluation_profile=evaluation_profile,
        target_authorization_payload=historical_payload,
    )
    assert tuple(canonical_bytes(item.to_dict()) for item in objects) == before_bytes
    assert tuple(item.profile_fingerprint for item in objects) == before_fingerprints
    assert tuple(item.is_launchable_runtime_profile for item in objects) == before_launchability
    assert canonical_bytes(historical_payload.to_dict()) == payload_bytes
    assert historical_payload.payload_fingerprint == payload_fingerprint
    assert evaluation_profile.is_launchable_runtime_profile is False
    forbidden_leakage = {
        "request_fingerprint",
        "resolution_status",
        "compatibility_result",
        "product_contract_id",
        "product_verdict",
        "evidence",
        "binding_authority_fingerprint",
    }
    assert forbidden_leakage.isdisjoint(authority.to_dict())
