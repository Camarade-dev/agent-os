from __future__ import annotations

import json
from pathlib import Path

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import NativeMissionProfile
from admissible.product_launcher.authoring import AuthoringError, author_runtime_contract
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher


EXPECTED_PLAN_NOTICES = {
    "authorship": "These verification obligations were explicitly authored by the owner.",
    "coverage": "Verification-plan coverage has not been assessed. Claims or requirements may lack an authorized verification obligation.",
    "non_execution": "These verification obligations describe intended evidence-acquisition procedures. They have not been executed and have produced no evidence.",
    "no_adjudication": "The presence of a verification obligation does not mean that its referenced claims are supported or adjudicated.",
    "independence": "Independence values are requirements of the plan, not evidence that those properties were achieved.",
    "procedure_binding": "Procedure references have not been validated against current runtime capabilities.",
    "runtime": "Claim-verification-plan V4 contracts are not launchable in the current runtime.",
}


def _configuration(tmp_path: Path) -> LauncherConfiguration:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    return LauncherConfiguration(
        source_repository=source.resolve(), required_source_head="a" * 40,
        run_parent=(tmp_path / "runs").resolve(),
        contract_documents_directory=(tmp_path / "documents").resolve(),
        executable="provider", executable_prefix_args=(), attestation_class="package-bin",
        model_default="model", timeout_default=60, timeout_maximum=3600,
        stdout_byte_limit=65536, stderr_byte_limit=65536,
        product_ui_bind_host="127.0.0.1", product_ui_bind_port=0,
        g2_bind_host="127.0.0.1", g2_bind_port=0,
        authorization_mode=AUTHORIZATION_MODE_PRECOMMITTED, open_browser=False,
    )


def _input(**changes: object) -> dict[str, object]:
    value = {
        "mission_text": "Deliver the requested artifact.",
        "gate_objective": "Deliver one bounded artifact.",
        "completion_conditions_text": "The artifact exists.",
        "required_material_paths": ["README.md"],
        "commit_message": "feat: deliver artifact",
    }
    value.update(changes)
    return value


def _claim(claim_id: str) -> dict[str, object]:
    return {"claim_id": claim_id, "statement": f"Statement {claim_id}",
            "obligation_level": "MANDATORY", "depends_on": [], "non_claims": []}


def _obligation(obligation_id: str = "zulu_first", claim_ids=None) -> dict[str, object]:
    return {
        "obligation_id": obligation_id,
        "claim_ids": claim_ids or ["claim_a"],
        "strategy": "CHECKPOINT_COMMAND",
        "procedure_reference": "owner_procedure",
        "acceptance_predicate": "EXIT_CODE_ZERO",
        "declared_coverage": "Owner-declared bounded coverage",
        "non_claims": ["Zulu exclusion", "Alpha exclusion"],
        "oracle_disclosed_to_subject": False,
        "independence_requirements": {
            "temporal": True, "artifact": False, "process": True,
            "information": True, "model": False, "organizational": True,
        },
        "negative_controls": [
            {"control_id": "zulu_control", "description": "Zulu control"},
            {"control_id": "alpha_control", "description": "Alpha control"},
        ],
        "reference_cases": ["zulu_case", "alpha_case"],
    }


def _author(tmp_path: Path, owner_input: dict[str, object], identity="a"):
    return author_runtime_contract(
        owner_input, launcher_configuration=_configuration(tmp_path),
        documents_directory=(tmp_path / "documents").resolve(),
        id_generator=lambda: identity * 32,
    )


def test_selection_matrix_and_absent_fields(tmp_path):
    v2 = _author(tmp_path / "v2", _input(), "a")
    v3 = _author(tmp_path / "v3", _input(result_claims=[_claim("claim_a")]), "b")
    v4 = _author(tmp_path / "v4", _input(
        result_claims=[_claim("claim_a")], claim_verification_plan=[_obligation()]), "c")
    assert [x.profile.schema_version for x in (v2, v3, v4)] == [
        "admissible_native_mission_profile_v2",
        "admissible_native_mission_profile_v3",
        "admissible_native_mission_profile_v4",
    ]
    assert "claim_verification_plan_authority" not in v2.contract_summary
    assert "claim_verification_plan_authority" not in v3.contract_summary
    assert canonical_bytes(v4.profile.to_dict()) == Path(v4.document_path).read_bytes()
    assert NativeMissionProfile.from_dict(v4.profile.to_dict()) == v4.profile


@pytest.mark.parametrize("plan", [None, []])
def test_explicit_null_or_empty_plan_rejected(tmp_path, plan):
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, _input(result_claims=[_claim("claim_a")], claim_verification_plan=plan))
    assert caught.value.to_dict() == {
        "error_code": "INVALID_CLAIM_VERIFICATION_PLAN",
        "safe_message_key": "authoring.verification_plan_nonempty_array_required",
        "field": "claim_verification_plan",
    }


def test_plan_without_claims_has_distinct_bounded_rejection(tmp_path):
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, _input(claim_verification_plan=[_obligation()]))
    assert caught.value.error_code == "VERIFICATION_PLAN_REQUIRES_RESULT_CLAIMS"
    assert "Traceback" not in json.dumps(caught.value.to_dict())


@pytest.mark.parametrize("mutation", [
    lambda p: [{**p[0], "unknown": "x"}],
    lambda p: [{k: v for k, v in p[0].items() if k != "strategy"}],
    lambda p: [{**p[0], "authorship": "OWNER_AUTHORED"}],
    lambda p: [{**p[0], "coverage_status": "NOT_ASSESSED"}],
    lambda p: [{**p[0], "identity_fingerprint": "a" * 64}],
    lambda p: [p[0], p[0]],
    lambda p: [{**p[0], "strategy": "UNKNOWN"}],
    lambda p: [{**p[0], "strategy": "HUMAN_RUBRIC_OBSERVATION"}],
    lambda p: [{**p[0], "claim_ids": ["missing"]}],
    lambda p: [{**p[0], "claim_ids": ["claim_a", "claim_a"]}],
    lambda p: [{**p[0], "oracle_disclosed_to_subject": 1}],
    lambda p: [{**p[0], "oracle_disclosed_to_subject": True}],
    lambda p: [{**p[0], "independence_requirements": {"temporal": True}}],
    lambda p: [{**p[0], "negative_controls": [{"control_id": "same", "description": "a"}, {"control_id": "same", "description": "b"}]}],
    lambda p: [{**p[0], "procedure_reference": "../unsafe"}],
    lambda p: [{**p[0], "reference_cases": ["../unsafe"]}],
])
def test_malformed_plan_cases_are_bounded_and_create_no_document(tmp_path, mutation):
    documents = tmp_path / "documents"
    with pytest.raises(AuthoringError) as caught:
        _author(tmp_path, _input(
            result_claims=[_claim("claim_a"), _claim("Claim_A")],
            claim_verification_plan=mutation([_obligation()]),
        ))
    assert caught.value.error_code in {"INVALID_CLAIM_VERIFICATION_PLAN", "BUILDER_REJECTED"}
    assert caught.value.field in {"claim_verification_plan", None}
    assert not documents.exists() or not list(documents.iterdir())
    assert not any(token in json.dumps(caught.value.to_dict()) for token in ("Traceback", "mission_profile", "C:\\"))


def test_v4_authority_order_fingerprint_and_review_contract(tmp_path):
    first = _obligation("zulu_first", ["claim_b", "claim_a"])
    second = _obligation("alpha_second", ["claim_a"])
    authored = _author(tmp_path / "base", _input(
        result_claims=[_claim("claim_a"), _claim("claim_b"), _claim("uncovered")],
        claim_verification_plan=[first, second]), "d")
    profile = authored.profile
    plan = profile.claim_verification_plan_authority
    assert profile.is_launchable_runtime_profile is False
    assert plan.authorship.value == "OWNER_AUTHORED"
    assert plan.coverage_status.value == "NOT_ASSESSED"
    assert [x.obligation_id for x in plan.verification_obligations] == ["zulu_first", "alpha_second"]
    assert plan.verification_obligations[0].claim_ids == ("claim_b", "claim_a")
    assert plan.verification_obligations[0].non_claims == ("Zulu exclusion", "Alpha exclusion")
    assert [x.control_id for x in plan.verification_obligations[0].negative_controls] == ["zulu_control", "alpha_control"]
    assert plan.verification_obligations[0].reference_cases == ("zulu_case", "alpha_case")
    summary = authored.contract_summary
    assert summary["claim_authority"] == profile.claim_authority.to_dict()
    assert summary["claim_verification_plan_authority"] == plan.to_dict()
    assert summary["verification_plan_review_notices"] == EXPECTED_PLAN_NOTICES
    assert summary["claim_review_notices"]["runtime"] == EXPECTED_PLAN_NOTICES["runtime"]
    changed = _author(tmp_path / "changed", _input(
        result_claims=[_claim("claim_a"), _claim("claim_b"), _claim("uncovered")],
        claim_verification_plan=[second, first]), "d")
    assert changed.profile_fingerprint != authored.profile_fingerprint


def test_v4_service_refuses_preparation_and_direct_launch_before_effects(tmp_path):
    ids = iter(f"{value:032x}" for value in range(1, 30))
    launcher = ProductLauncher(_configuration(tmp_path), verify_head=False,
        id_generator=lambda: next(ids), browser_opener=lambda _url: None)
    calls = []
    launcher.proxy_g2 = lambda *args, **kwargs: calls.append((args, kwargs)) or (599, {})
    launcher._preflight_application = lambda **kwargs: (_ for _ in ()).throw(AssertionError("preflight reached"))
    try:
        status, body = launcher.author_and_validate(_input(
            result_claims=[_claim("claim_a")], claim_verification_plan=[_obligation()]))
        assert status == 200 and body["runtime_launchable"] is False
        contract_id = body["contract_id"]
        refusal = (409, {"error": "CLAIM_VERIFICATION_PLAN_V4_NOT_LAUNCHABLE"})
        assert launcher.enqueue_preparation(contract_id) == refusal
        assert launcher.launch_run(contract_id=contract_id, preparation_id="cross-bound",
            owner_authorization="owner", owner_authorization_digest="f" * 64) == refusal
        assert calls == []
        assert launcher._preparations._items == {}
        assert launcher._launched_runs == {}
        assert not any(launcher.configuration.run_parent.iterdir())
    finally:
        launcher.close()


def test_v4_ui_is_separate_text_only_fail_closed_and_overflow_bounded():
    root = Path(__file__).resolve().parents[1]
    script = (root / "admissible/product_ui/app.js").read_text(encoding="utf-8")
    html = (root / "admissible/product_ui/index.html").read_text(encoding="utf-8")
    css = (root / "admissible/product_ui/app.css").read_text(encoding="utf-8")
    assert 'id="claim-verification-plan"' in html
    assert 'id="contract-verification-plan-review"' in html
    assert "normalizedVerificationPlan" in script
    assert "No partial obligation list is shown." in script
    assert "item.textContent=value" in script
    assert "innerHTML" not in script and "insertAdjacentHTML" not in script
    assert 'byId("prepare-button").hidden=!launchable' in script
    assert ".verification-obligation-list" in css
    assert "overflow-wrap:anywhere" in css and "word-break:break-word" in css
    assert ".claim-list" in css
