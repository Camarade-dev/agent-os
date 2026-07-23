from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    MISSION_PROFILE_SCHEMA_VERSION_V3,
    MISSION_PROFILE_SCHEMA_VERSION_V4,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
    ProfileCheckpointCommand,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.native_canary import (
    create_canary_session,
    run_native_mission_application,
)
from admissible.product_launcher.authoring import (
    GOLDEN_EXACT_CONTRACT_FIELDS,
    GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256,
    AuthoringError,
    author_runtime_contract,
)
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_PRECOMMITTED,
    GOLDEN_TEMPLATE_ID,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher
from admissible.product_launcher.preflight import AuthorizationPreparation, STATE_READY


EXPECTED_BINDING_NOTICES = {
    "authorship": "These evidence bindings were explicitly authored by the owner.",
    "coverage": (
        "Evidence-binding coverage has not been assessed. Verification obligations "
        "may remain unbound."
    ),
    "authority_relationship": (
        "Each binding authorizes a relationship between a verification obligation "
        "and an in-profile evidence-source authority."
    ),
    "no_evidence_existence": (
        "A binding does not assert that an evidence record exists or will be produced."
    ),
    "no_resolution_or_eligibility": (
        "A binding does not assert that a source has been resolved or that any "
        "produced evidence is eligible."
    ),
    "no_obligation_or_claim_result": (
        "A binding does not mean that an obligation is satisfied or that a claim is "
        "supported or adjudicated."
    ),
    "source_identity": (
        "Source references identify pre-authorized profile authorities, not post-run "
        "evidence records."
    ),
    "procedure_reference_separation": (
        "An obligation's procedure reference is not its evidence-source identity."
    ),
    "human_rubric_limitation": (
        "Human-rubric obligations currently have no bindable evidence-source authority."
    ),
    "runtime": (
        "Evidence-binding V5 contracts are not launchable in the current runtime."
    ),
}
V5_REFUSAL = (
    409,
    {"error": "VERIFICATION_EVIDENCE_BINDING_V5_NOT_LAUNCHABLE"},
)


def _configuration(tmp_path: Path) -> LauncherConfiguration:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    return LauncherConfiguration(
        source_repository=source.resolve(),
        required_source_head="a" * 40,
        run_parent=(tmp_path / "runs").resolve(),
        contract_documents_directory=(tmp_path / "documents").resolve(),
        executable="provider",
        executable_prefix_args=(),
        attestation_class="package-bin",
        model_default="model",
        timeout_default=60,
        timeout_maximum=3600,
        stdout_byte_limit=65536,
        stderr_byte_limit=65536,
        product_ui_bind_host="127.0.0.1",
        product_ui_bind_port=0,
        g2_bind_host="127.0.0.1",
        g2_bind_port=0,
        authorization_mode=AUTHORIZATION_MODE_PRECOMMITTED,
        open_browser=False,
    )


def _input(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "mission_text": "Deliver the requested artifact.",
        "gate_objective": "Deliver one bounded artifact.",
        "completion_conditions_text": "The artifact exists.",
        "required_material_paths": ["README.md"],
        "commit_message": "feat: deliver artifact",
    }
    value.update(changes)
    return value


def _claim(claim_id: str = "claim_a") -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "statement": f"Statement {claim_id}",
        "obligation_level": "MANDATORY",
        "depends_on": [],
        "non_claims": [],
    }


def _obligation(
    obligation_id: str = "obligation_a",
    *,
    strategy: str = "CHECKPOINT_COMMAND",
    procedure_reference: str = "descriptive_owner_procedure",
    claim_id: str = "claim_a",
) -> dict[str, object]:
    human = strategy == "HUMAN_RUBRIC_OBSERVATION"
    return {
        "obligation_id": obligation_id,
        "claim_ids": [claim_id],
        "strategy": strategy,
        "procedure_reference": procedure_reference,
        "acceptance_predicate": "HUMAN_RUBRIC_PASS" if human else "EXIT_CODE_ZERO",
        "declared_coverage": "Owner-declared bounded coverage",
        "non_claims": [],
        "oracle_disclosed_to_subject": strategy == "FROZEN_BEHAVIORAL_VERIFIER",
        "independence_requirements": {
            "temporal": True,
            "artifact": True,
            "process": True,
            "information": strategy != "FROZEN_BEHAVIORAL_VERIFIER",
            "model": True,
            "organizational": False,
        },
        "negative_controls": [],
        "reference_cases": [],
    }


def _binding(
    binding_id: str = "binding_a",
    obligation_id: str = "obligation_a",
    *,
    source_type: str = "CHECKPOINT_COMMAND_AUTHORITY",
    source_reference: object = "workspace-marker-check",
) -> dict[str, object]:
    return {
        "binding_id": binding_id,
        "obligation_id": obligation_id,
        "source_authority_type": source_type,
        "source_authority_reference": source_reference,
    }


def _v5_input(
    *,
    claims: list[dict[str, object]] | None = None,
    plan: list[dict[str, object]] | None = None,
    bindings: object = None,
) -> dict[str, object]:
    return _input(
        result_claims=claims or [_claim()],
        claim_verification_plan=plan or [_obligation()],
        verification_evidence_bindings=(
            [_binding()] if bindings is None else bindings
        ),
    )


def _author(
    tmp_path: Path,
    owner_input: dict[str, object],
    identity: str = "a",
    **kwargs: object,
):
    return author_runtime_contract(
        owner_input,
        launcher_configuration=_configuration(tmp_path),
        documents_directory=(tmp_path / "documents").resolve(),
        id_generator=lambda: identity * 32,
        **kwargs,
    )


def test_exact_v2_v3_v4_v5_selection_matrix_and_absent_fields(tmp_path):
    v2 = _author(tmp_path / "v2", _input(), "a")
    v3 = _author(tmp_path / "v3", _input(result_claims=[_claim()]), "b")
    v4 = _author(
        tmp_path / "v4",
        _input(result_claims=[_claim()], claim_verification_plan=[_obligation()]),
        "c",
    )
    v5 = _author(tmp_path / "v5", _v5_input(), "d")

    assert [item.profile.schema_version for item in (v2, v3, v4, v5)] == [
        MISSION_PROFILE_SCHEMA_VERSION_V2,
        MISSION_PROFILE_SCHEMA_VERSION_V3,
        MISSION_PROFILE_SCHEMA_VERSION_V4,
        MISSION_PROFILE_SCHEMA_VERSION_V5,
    ]
    binding_fields = {
        "verification_evidence_binding_authority",
        "verification_evidence_binding_review_notices",
    }
    assert all(binding_fields.isdisjoint(item.contract_summary) for item in (v2, v3, v4))
    assert "claim_authority" not in v2.contract_summary
    assert "claim_verification_plan_authority" not in v2.contract_summary
    assert "claim_verification_plan_authority" not in v3.contract_summary
    assert canonical_bytes(v5.profile.to_dict()) == Path(v5.document_path).read_bytes()
    assert NativeMissionProfile.from_dict(v5.profile.to_dict()) == v5.profile


@pytest.mark.parametrize(
    ("changes", "error_code"),
    [
        ({"verification_evidence_bindings": [_binding()]}, "EVIDENCE_BINDINGS_REQUIRE_RESULT_CLAIMS"),
        (
            {"result_claims": [_claim()], "verification_evidence_bindings": [_binding()]},
            "EVIDENCE_BINDINGS_REQUIRE_VERIFICATION_PLAN",
        ),
        (
            {
                "claim_verification_plan": [_obligation()],
                "verification_evidence_bindings": [_binding()],
            },
            "EVIDENCE_BINDINGS_REQUIRE_RESULT_CLAIMS",
        ),
    ],
)
def test_binding_presence_dependencies_fail_closed_before_persistence(
    tmp_path, changes, error_code
):
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, _input(**changes))
    assert caught.value.error_code == error_code
    assert caught.value.field == "verification_evidence_bindings"
    assert not (tmp_path / "documents").exists()


@pytest.mark.parametrize("value", [None, [], {}, "bindings", 1, True])
def test_null_empty_and_malformed_bindings_never_fall_back_to_v4(tmp_path, value):
    with pytest.raises(AuthoringError) as caught:
        _author(
            tmp_path,
            _input(
                result_claims=[_claim()],
                claim_verification_plan=[_obligation()],
                verification_evidence_bindings=value,
            ),
        )
    assert caught.value.error_code == "INVALID_VERIFICATION_EVIDENCE_BINDINGS"
    assert caught.value.field == "verification_evidence_bindings"
    assert not (tmp_path / "documents").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda item: {**item, "unknown": "x"},
        lambda item: {key: value for key, value in item.items() if key != "binding_id"},
        lambda item: {**item, "authorship": "OWNER_AUTHORED"},
        lambda item: {**item, "coverage_status": "NOT_ASSESSED"},
        lambda item: {**item, "identity_fingerprint": "a" * 64},
        lambda item: {**item, "profile_fingerprint": "a" * 64},
        lambda item: {**item, "produced_evidence_id": "record"},
        lambda item: {**item, "human_disposition": "ACCEPTED"},
        lambda item: {**item, "binding_id": "bad binding"},
        lambda item: {**item, "obligation_id": "../bad"},
        lambda item: {**item, "source_authority_type": "HUMAN_RUBRIC_OBSERVATION"},
        lambda item: {**item, "source_authority_reference": 42},
    ],
)
def test_owner_cannot_inject_binding_authority_or_malformed_binding_fields(
    tmp_path, mutation
):
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, _v5_input(bindings=[mutation(_binding())]))
    public = caught.value.to_dict()
    assert public == {
        "error_code": "INVALID_VERIFICATION_EVIDENCE_BINDINGS",
        "safe_message_key": "authoring.invalid_verification_evidence_bindings",
        "field": "verification_evidence_bindings",
    }
    assert not any(
        token in json.dumps(public)
        for token in ("Traceback", "mission_profile", "ValueError", "C:\\", "provider")
    )
    assert not (tmp_path / "documents").exists()


def test_unknown_top_level_field_is_bounded_and_creates_nothing(tmp_path):
    owner_input = _v5_input()
    owner_input["unknown_owner_field"] = "x"
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, owner_input)
    assert caught.value.to_dict() == {
        "error_code": "UNKNOWN_FIELD",
        "safe_message_key": "authoring.unknown_field",
        "field": "unknown_owner_field",
    }
    assert not (tmp_path / "documents").exists()


@pytest.mark.parametrize(
    ("plan", "bindings"),
    [
        ([_obligation()], [_binding(), _binding()]),
        (
            [_obligation("one"), _obligation("two")],
            [_binding("first", "one"), _binding("second", "one")],
        ),
        ([_obligation()], [_binding(obligation_id="absent")]),
        ([_obligation()], [_binding(obligation_id="Obligation_A")]),
        ([_obligation()], [_binding(source_reference="missing-command")]),
        ([_obligation()], [_binding(source_reference="Workspace-Marker-Check")]),
        (
            [_obligation(procedure_reference="missing-command")],
            [_binding(source_reference="missing-command")],
        ),
        (
            [_obligation()],
            [_binding(source_reference="OWNER_ACCEPTED")],
        ),
        (
            [_obligation()],
            [
                _binding(
                    source_type="FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY",
                    source_reference="0" * 64,
                )
            ],
        ),
        (
            [_obligation("human", strategy="HUMAN_RUBRIC_OBSERVATION")],
            [_binding(obligation_id="human")],
        ),
    ],
)
def test_canonical_v5_cross_validation_rejects_invalid_binding_relationships(
    tmp_path, plan, bindings
):
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, _v5_input(plan=plan, bindings=bindings))
    assert caught.value.to_dict() == {
        "error_code": "INVALID_VERIFICATION_EVIDENCE_BINDINGS",
        "safe_message_key": "authoring.invalid_verification_evidence_bindings",
        "field": "verification_evidence_bindings",
    }
    assert not (tmp_path / "documents").exists()


def test_owner_binding_order_exact_authority_and_profile_fingerprint(tmp_path):
    claims = [_claim("claim_a"), _claim("claim_b")]
    plan = [
        _obligation("zulu_first", claim_id="claim_a"),
        _obligation("alpha_second", claim_id="claim_b"),
    ]
    first = _binding("zulu_binding", "zulu_first")
    second = _binding("alpha_binding", "alpha_second")
    authored = _author(
        tmp_path / "ordered",
        _v5_input(claims=claims, plan=plan, bindings=[first, second]),
        "d",
    )
    reordered = _author(
        tmp_path / "reordered",
        _v5_input(claims=claims, plan=plan, bindings=[second, first]),
        "d",
    )
    authority = authored.profile.verification_evidence_binding_authority
    assert authority.authorship.value == "OWNER_AUTHORED"
    assert authority.coverage_status.value == "NOT_ASSESSED"
    assert [binding.to_dict() for binding in authority.bindings] == [first, second]
    assert authored.profile_fingerprint != reordered.profile_fingerprint
    assert (
        authored.contract_summary["verification_evidence_binding_authority"]
        == authority.to_dict()
    )


def test_non_first_checkpoint_reference_and_checkpoint_reordering_are_identity_based(
    tmp_path
):
    commands = (
        ProfileCheckpointCommand("zulu-command", ("python", "-V"), 30, 8192),
        ProfileCheckpointCommand("mike-command", ("python", "-V"), 30, 8192),
        ProfileCheckpointCommand("alpha-command", ("python", "-V"), 30, 8192),
    )

    def builder_for(order):
        def build(**kwargs):
            kwargs["checkpoint_commands"] = order
            return create_native_mission_profile(**kwargs)

        return build

    owner_input = _v5_input(
        bindings=[_binding(source_reference="mike-command")]
    )
    authored = _author(
        tmp_path / "first",
        owner_input,
        "e",
        profile_builder=builder_for(commands),
    )
    reordered = _author(
        tmp_path / "second",
        owner_input,
        "e",
        profile_builder=builder_for((commands[2], commands[0], commands[1])),
    )
    assert (
        authored.profile.verification_evidence_binding_authority.bindings[
            0
        ].source_authority_reference
        == "mike-command"
    )
    assert (
        reordered.profile.verification_evidence_binding_authority.bindings[
            0
        ].source_authority_reference
        == "mike-command"
    )
    assert reordered.profile.checkpoint_commands[0].command_id == "alpha-command"


def _golden_v5_input(source_reference: str) -> dict[str, object]:
    owner_input = {
        key: list(value) if isinstance(value, tuple) else value
        for key, value in GOLDEN_EXACT_CONTRACT_FIELDS.items()
    }
    owner_input.update(
        {
            "template_id": GOLDEN_TEMPLATE_ID,
            "result_claims": [_claim()],
            "claim_verification_plan": [
                _obligation(
                    strategy="FROZEN_BEHAVIORAL_VERIFIER",
                    procedure_reference="descriptive_behavioral_procedure",
                )
            ],
            "verification_evidence_bindings": [
                _binding(
                    source_type="FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY",
                    source_reference=source_reference,
                )
            ],
        }
    )
    return owner_input


def test_frozen_behavioral_reference_is_exact_and_profile_local(tmp_path):
    valid = _author(
        tmp_path / "valid",
        _golden_v5_input(GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256),
        "f",
    )
    assert (
        valid.profile.verification_evidence_binding_authority.bindings[
            0
        ].source_authority_reference
        == GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256
    )
    for foreign_digest in ("0" * 64, "A" * 64):
        with pytest.raises(AuthoringError) as caught:
            _author(
                tmp_path / foreign_digest[:1],
                _golden_v5_input(foreign_digest),
                "f",
            )
        assert caught.value.error_code == "INVALID_VERIFICATION_EVIDENCE_BINDINGS"


def test_human_rubric_only_plan_stays_v4_without_bindings_and_rejects_binding(
    tmp_path,
):
    plan = [_obligation("human", strategy="HUMAN_RUBRIC_OBSERVATION")]
    v4 = _author(
        tmp_path / "v4",
        _input(result_claims=[_claim()], claim_verification_plan=plan),
        "a",
    )
    assert v4.profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4
    assert "verification_evidence_binding_authority" not in v4.contract_summary
    with pytest.raises(AuthoringError) as caught:
        _author(
            tmp_path / "rejected",
            _v5_input(plan=plan, bindings=[_binding(obligation_id="human")]),
            "b",
        )
    assert caught.value.error_code == "INVALID_VERIFICATION_EVIDENCE_BINDINGS"


def test_binding_bounds_partial_coverage_and_shared_source(tmp_path):
    claims = [_claim()]
    obligations = [_obligation(f"obligation_{index:03d}") for index in range(256)]
    bindings = [
        _binding(f"binding_{index:03d}", f"obligation_{index:03d}")
        for index in range(256)
    ]
    maximum = _author(
        tmp_path / "maximum",
        _v5_input(claims=claims, plan=obligations, bindings=bindings),
        "1",
    )
    assert len(maximum.profile.verification_evidence_binding_authority.bindings) == 256
    with pytest.raises(AuthoringError) as caught:
        _author(
            tmp_path / "overflow",
            _v5_input(
                claims=claims,
                plan=obligations,
                bindings=bindings + [_binding("overflow", "obligation_000")],
            ),
            "2",
        )
    assert caught.value.error_code == "INVALID_VERIFICATION_EVIDENCE_BINDINGS"

    two_obligations = [_obligation("one"), _obligation("two")]
    partial = _author(
        tmp_path / "partial",
        _v5_input(plan=two_obligations, bindings=[_binding("first", "one")]),
        "3",
    )
    shared = _author(
        tmp_path / "shared",
        _v5_input(
            plan=two_obligations,
            bindings=[_binding("first", "one"), _binding("second", "two")],
        ),
        "4",
    )
    assert len(partial.profile.verification_evidence_binding_authority.bindings) == 1
    assert {
        binding.source_authority_reference
        for binding in shared.profile.verification_evidence_binding_authority.bindings
    } == {"workspace-marker-check"}


def test_v5_summary_has_four_distinct_sections_and_all_ten_exact_notices(tmp_path):
    authored = _author(tmp_path, _v5_input(), "5")
    summary = authored.contract_summary
    assert summary["profile_fingerprint"] == authored.profile_fingerprint
    assert summary["claim_authority"] == authored.profile.claim_authority.to_dict()
    assert (
        summary["claim_verification_plan_authority"]
        == authored.profile.claim_verification_plan_authority.to_dict()
    )
    assert (
        summary["verification_evidence_binding_authority"]
        == authored.profile.verification_evidence_binding_authority.to_dict()
    )
    assert summary["verification_evidence_binding_review_notices"] == EXPECTED_BINDING_NOTICES
    assert len(summary["verification_evidence_binding_review_notices"]) == 10
    assert summary["gate_clauses"] is not summary["claim_authority"]["claims"]
    assert (
        summary["claim_authority"]["claims"]
        is not summary["claim_verification_plan_authority"]["verification_obligations"]
    )
    assert (
        summary["claim_verification_plan_authority"]["verification_obligations"]
        is not summary["verification_evidence_binding_authority"]["bindings"]
    )
    lowered = " ".join(EXPECTED_BINDING_NOTICES.values()).lower()
    for prohibited in (
        "resolved evidence",
        "eligible evidence",
        "verified claim",
        "supported claim",
        "passed obligation",
        "failed obligation",
        "successful binding",
    ):
        assert prohibited not in lowered


def test_v5_ui_contract_is_text_only_separate_fail_closed_and_bounded():
    root = Path(__file__).resolve().parents[1]
    script = (root / "admissible/product_ui/app.js").read_text(encoding="utf-8")
    html = (root / "admissible/product_ui/index.html").read_text(encoding="utf-8")
    css = (root / "admissible/product_ui/app.css").read_text(encoding="utf-8")
    assert 'id="verification-evidence-bindings"' in html
    assert 'id="contract-evidence-binding-review"' in html
    assert "normalizedEvidenceBindingReview" in script
    assert "No partial binding list is shown." in script
    assert 'appendFact(details,"Source authority reference"' in script
    assert 'appendFact(details,"Produced evidence"' not in script
    assert "innerHTML" not in script
    assert "outerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "document.write" not in script
    assert "eval(" not in script
    assert 'byId("prepare-button").hidden=!launchable' in script
    assert ".evidence-binding-list" in css
    assert "overflow-wrap:anywhere" in css
    assert "word-break:break-word" in css


def test_product_authored_v5_server_refuses_prepare_launch_recovery_before_effects(
    tmp_path,
):
    ids = iter(f"{value:032x}" for value in range(1, 100))
    launcher = ProductLauncher(
        _configuration(tmp_path),
        verify_head=False,
        id_generator=lambda: next(ids),
        browser_opener=lambda _url: None,
    )
    proxy_calls = []
    launcher.proxy_g2 = (
        lambda *args, **kwargs: proxy_calls.append((args, kwargs)) or (599, {})
    )
    launcher._preflight_application = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("preflight reached")
    )
    try:
        status, body = launcher.author_and_validate(_v5_input())
        assert status == 200
        assert body["runtime_launchable"] is False
        contract_id = body["contract_id"]
        assert launcher.enqueue_preparation(contract_id) == V5_REFUSAL
        assert (
            launcher.launch_run(
                contract_id=contract_id,
                preparation_id="fabricated",
                owner_authorization="owner",
                owner_authorization_digest="f" * 64,
            )
            == V5_REFUSAL
        )
        assert launcher.create_recovery(contract_id) == V5_REFUSAL
        assert (
            launcher.create_recovery(body["generated_ids"]["run_id"])
            == V5_REFUSAL
        )
        assert proxy_calls == []
        assert launcher._preparations._items == {}
        assert launcher._recoveries.values() == []
        assert launcher._launched_runs == {}
        assert not any(launcher.configuration.run_parent.iterdir())
        assert not (launcher._recoveries_directory).exists()
    finally:
        launcher.close()


def test_v5_preparation_and_contract_cross_associations_fail_closed(tmp_path):
    ids = iter(f"{value:032x}" for value in range(200, 300))
    launcher = ProductLauncher(
        _configuration(tmp_path),
        verify_head=False,
        id_generator=lambda: next(ids),
        browser_opener=lambda _url: None,
    )
    launcher.proxy_g2 = lambda method, path, body=None: (
        200,
        {"contract_id": "runtime-v2-contract"},
    )
    try:
        _, v2 = launcher.author_and_validate(_input())
        _, v4 = launcher.author_and_validate(
            _input(
                result_claims=[_claim()],
                claim_verification_plan=[_obligation()],
            )
        )
        _, v5 = launcher.author_and_validate(_v5_input())
        assert v2["contract_id"] == "runtime-v2-contract"
        for preparation_id, contract_id in (
            ("v2-preparation", v2["contract_id"]),
            ("v4-preparation", v4["contract_id"]),
            ("v5-preparation", v5["contract_id"]),
        ):
            launcher._preparations.create(
                AuthorizationPreparation(
                    preparation_id=preparation_id,
                    contract_id=contract_id,
                    authorization_mode=AUTHORIZATION_MODE_PRECOMMITTED,
                    state=STATE_READY,
                    created_at="2026-07-23T00:00:00Z",
                )
            )
        for foreign_preparation in ("v2-preparation", "v4-preparation"):
            assert (
                launcher.launch_run(
                    contract_id=v5["contract_id"],
                    preparation_id=foreign_preparation,
                    owner_authorization="owner",
                    owner_authorization_digest="f" * 64,
                )
                == V5_REFUSAL
            )
        for foreign_contract in (v2["contract_id"], v4["contract_id"]):
            expected = (
                (409, {"error": "PREPARATION_CONTRACT_MISMATCH"})
                if foreign_contract == v2["contract_id"]
                else (
                    409,
                    {"error": "CLAIM_VERIFICATION_PLAN_V4_NOT_LAUNCHABLE"},
                )
            )
            assert launcher.launch_run(
                contract_id=foreign_contract,
                preparation_id="v5-preparation",
                owner_authorization="owner",
                owner_authorization_digest="f" * 64,
            ) == expected
        assert launcher._launched_runs == {}
        assert not any(launcher.configuration.run_parent.iterdir())
    finally:
        launcher.close()


def test_product_authored_v5_reaches_no_runtime_payload_process_or_provider(
    tmp_path,
):
    authored = _author(tmp_path / "authored", _v5_input(), "6")
    profile = authored.profile
    with pytest.raises(ValueError, match="v2 schema"):
        load_native_mission_profile_document(Path(authored.document_path))
    with pytest.raises(ValueError, match="launchable runtime-v2"):
        create_canary_session(session_id=profile.session_id, profile=profile)
    with mock.patch(
        "admissible.delegated_gate.native_canary.subprocess.run",
        side_effect=AssertionError("process reached"),
    ):
        with pytest.raises(ValueError, match="launchable runtime-v2"):
            run_native_mission_application(
                source_repository=tmp_path / "source",
                required_source_head="0" * 40,
                run_root=tmp_path / "runtime-run",
                run_id=profile.run_id,
                session_id=profile.session_id,
                executable="provider",
                profile=profile,
                preflight_only=True,
            )
    assert not (tmp_path / "runtime-run").exists()

    from test_admissible_workflow_recovery_profile import _payload_harness

    from test_admissible_claim_verification_plan_v4 import _v2_profile

    payload_root = tmp_path / "payload"
    payload_root.mkdir()
    harness = _payload_harness(payload_root, _v2_profile())
    candidate = replace(harness.payload, mission_profile=profile)
    with mock.patch(
        "admissible.delegated_gate.native_canary.create_canary_session",
        side_effect=AssertionError("authorization payload construction reached"),
    ):
        with pytest.raises(
            ValueError,
            match="runtime-v4 authorization requires the launchable runtime-v2 schema",
        ):
            candidate.validated()
