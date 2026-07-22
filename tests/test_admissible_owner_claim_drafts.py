from __future__ import annotations

from pathlib import Path

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import NativeMissionProfile
from admissible.product_launcher.authoring import (
    CLAIM_ADJUDICATION_NOTICE,
    CLAIM_AUTHORSHIP_NOTICE,
    CLAIM_COVERAGE_NOTICE,
    CLAIM_RUNTIME_NOTICE,
    AuthoringError,
    author_runtime_contract,
)
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher


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


def _owner_input(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "mission_text": "Deliver the requested artifact.",
        "gate_objective": "Deliver one bounded artifact.",
        "completion_conditions_text": "The artifact exists.",
        "required_material_paths": ["README.md"],
        "commit_message": "feat: deliver artifact",
    }
    value.update(changes)
    return value


def _claim(claim_id: str, *, depends_on: list[str] | None = None) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "statement": f"Statement for {claim_id}",
        "obligation_level": "MANDATORY",
        "depends_on": depends_on or [],
        "non_claims": [f"Not promised by {claim_id}"],
    }


def _author(tmp_path: Path, inputs: dict[str, object], identity: str):
    return author_runtime_contract(
        inputs,
        launcher_configuration=_configuration(tmp_path),
        documents_directory=(tmp_path / "documents").resolve(),
        id_generator=lambda: identity * 32,
    )


def test_explicit_owner_claims_construct_canonical_ordered_v3_review(tmp_path):
    claims = [_claim("foundation"), _claim("delivery", depends_on=["foundation"])]
    authored = _author(tmp_path, _owner_input(result_claims=claims), "a")
    profile = NativeMissionProfile.from_dict(authored.profile.to_dict())
    assert profile.schema_version == "admissible_native_mission_profile_v3"
    assert profile.is_launchable_runtime_profile is False
    assert profile.claim_authority.authorship.value == "OWNER_AUTHORED"
    assert profile.claim_authority.coverage_status.value == "NOT_ASSESSED"
    assert [claim.claim_id for claim in profile.claim_authority.claims] == ["foundation", "delivery"]
    assert profile.claim_authority.claims[1].depends_on == ("foundation",)
    assert profile.claim_authority.claims[0].non_claims == ("Not promised by foundation",)
    summary = authored.contract_summary
    assert summary["claim_authority"] == profile.claim_authority.to_dict()
    assert summary["gate_clauses"] and "claims" not in summary["gate_clauses"]
    assert list(summary["claim_review_notices"].values()) == [
        CLAIM_AUTHORSHIP_NOTICE,
        CLAIM_COVERAGE_NOTICE,
        CLAIM_ADJUDICATION_NOTICE,
        CLAIM_RUNTIME_NOTICE,
    ]


def test_absent_claims_preserve_v2_and_omit_claim_presentation(tmp_path):
    authored = _author(tmp_path, _owner_input(), "b")
    profile = authored.profile
    assert profile.schema_version == "admissible_native_mission_profile_v2"
    assert profile.is_launchable_runtime_profile is True
    assert "claim_authority" not in authored.contract_summary
    assert "claim_review_notices" not in authored.contract_summary
    assert canonical_bytes(profile.to_dict()) == Path(authored.document_path).read_bytes()


@pytest.mark.parametrize("value", [None, []])
def test_explicit_empty_or_null_claims_fail_closed(tmp_path, value):
    with pytest.raises(AuthoringError) as error:
        _author(tmp_path, _owner_input(result_claims=value), "c")
    assert error.value.error_code == "INVALID_RESULT_CLAIMS"
    assert error.value.field == "result_claims"


@pytest.mark.parametrize(
    "claims",
    [
        [{**_claim("a"), "authorship": "TEMPLATE_AUTHORED"}],
        [{**_claim("a"), "coverage_status": "NOT_ASSESSED"}],
        [_claim("a"), _claim("a")],
        [_claim("a", depends_on=["missing"])],
        [_claim("a", depends_on=["b"]), _claim("b", depends_on=["a"])],
    ],
)
def test_malformed_injected_duplicate_missing_and_cyclic_claims_fail_closed(tmp_path, claims):
    with pytest.raises(AuthoringError) as error:
        _author(tmp_path, _owner_input(result_claims=claims), "d")
    assert error.value.error_code == "INVALID_RESULT_CLAIMS"


def test_claim_content_and_order_change_profile_fingerprint(tmp_path):
    first = _author(tmp_path / "one", _owner_input(result_claims=[_claim("a"), _claim("b")]), "e")
    reordered = _author(tmp_path / "two", _owner_input(result_claims=[_claim("b"), _claim("a")]), "e")
    changed = _author(tmp_path / "three", _owner_input(result_claims=[{**_claim("a"), "statement": "Changed"}, _claim("b")]), "e")
    assert len({first.profile_fingerprint, reordered.profile_fingerprint, changed.profile_fingerprint}) == 3


def test_v3_review_and_direct_launch_refusal_reach_no_runtime_path(tmp_path):
    counter = iter(f"{value:032x}" for value in range(1, 20))
    launcher = ProductLauncher(
        _configuration(tmp_path),
        verify_head=False,
        id_generator=lambda: next(counter),
        browser_opener=lambda _url: None,
    )
    proxy_calls: list[tuple[object, ...]] = []
    preflight_calls: list[tuple[object, ...]] = []
    launcher.proxy_g2 = lambda *args, **kwargs: proxy_calls.append((args, kwargs)) or (599, {})
    launcher._preflight_application = lambda **kwargs: preflight_calls.append((kwargs,)) or (1, b"")
    try:
        status, body = launcher.author_and_validate(
            _owner_input(result_claims=[_claim("delivery")])
        )
        assert status == 200
        assert body["runtime_launchable"] is False
        assert body["contract_summary"]["schema_version"] == "admissible_native_mission_profile_v3"
        assert proxy_calls == []
        contract_id = body["contract_id"]
        assert launcher.enqueue_preparation(contract_id) == (
            409,
            {"error": "CLAIM_AWARE_V3_NOT_LAUNCHABLE"},
        )
        assert launcher.launch_run(
            contract_id=contract_id,
            preparation_id="bypass",
            owner_authorization="owner phrase",
            owner_authorization_digest="f" * 64,
        ) == (409, {"error": "CLAIM_AWARE_V3_NOT_LAUNCHABLE"})
        assert proxy_calls == []
        assert preflight_calls == []
        assert launcher._preparations._items == {}
        assert launcher._launched_runs == {}
        assert not Path(launcher.configuration.run_parent).exists() or not any(
            Path(launcher.configuration.run_parent).iterdir()
        )
    finally:
        launcher.close()


def test_claim_review_ui_is_text_only_fail_closed_and_overflow_bounded():
    root = Path(__file__).resolve().parents[1]
    script = (root / "admissible/product_ui/app.js").read_text(encoding="utf-8")
    html = (root / "admissible/product_ui/index.html").read_text(encoding="utf-8")
    css = (root / "admissible/product_ui/app.css").read_text(encoding="utf-8")
    assert 'id="result-claims"' in html
    assert 'id="contract-claim-review"' in html
    assert "normalizedClaimReview" in script
    assert "No partial claim list is shown." in script
    assert 'title.textContent=claim.claim_id' in script
    assert 'statement.textContent=claim.statement' in script
    assert "innerHTML" not in script
    assert ".claim-list" in css and "overflow-wrap:anywhere" in css
    assert "word-break:break-word" in css
