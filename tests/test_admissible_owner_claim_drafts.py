from __future__ import annotations

import json
from pathlib import Path

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.mission_profile import NativeMissionProfile
from admissible.product_launcher.authoring import (
    AuthoringError,
    author_runtime_contract,
)
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher


# Test-owned acceptance literals.  Do not replace these with imports from the
# implementation: these assertions are intended to catch semantic rewording.
EXPECTED_CLAIM_NOTICES = {
    "authorship": "These result claims were explicitly authored by the owner.",
    "coverage": (
        "Claim-set coverage has not been assessed. Requirements omitted from this "
        "claim set may remain unrepresented."
    ),
    "adjudication": (
        "These claims are part of the draft contract but have not been adjudicated."
    ),
    "runtime": "Claim-aware V3 contracts are not launchable in the current runtime.",
}
FORBIDDEN_REVIEW_CLAIMS = (
    "verified",
    "fully supported",
    "adjudicated successfully",
    "coverage complete",
    "admitted",
    "passed",
)
V2_SUMMARY_KEYS = {
    "schema_version",
    "profile_id",
    "run_id",
    "session_id",
    "gate_id",
    "mission_id",
    "workspace_source_kind",
    "verification_mode",
    "gate_clauses",
    "template_id",
}


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


def _ordered_claims() -> list[dict[str, object]]:
    return [
        {
            **_claim("zulu-owner-first"),
            "statement": "Required material paths exist, as a distinct result claim.",
            "depends_on": ["mike-owner-second", "alpha-owner-third", "tango-owner-fourth"],
            "non_claims": ["Zulu exclusion", "Mike exclusion", "Alpha exclusion"],
        },
        {
            **_claim("mike-owner-second"),
            "statement": "Exactly one local result is described by the owner.",
        },
        {
            **_claim("alpha-owner-third"),
            "statement": "Owner claim resembling, but not becoming, a gate clause.",
        },
        {
            **_claim("tango-owner-fourth"),
            "statement": "A fourth result keeps three dependencies non-vacuous.",
        },
    ]


def _author(tmp_path: Path, inputs: dict[str, object], identity: str):
    return author_runtime_contract(
        inputs,
        launcher_configuration=_configuration(tmp_path),
        documents_directory=(tmp_path / "documents").resolve(),
        id_generator=lambda: identity * 32,
    )


def test_explicit_owner_claims_construct_canonical_ordered_v3_review(tmp_path):
    claims = _ordered_claims()
    authored = _author(tmp_path, _owner_input(result_claims=claims), "a")
    profile = NativeMissionProfile.from_dict(authored.profile.to_dict())
    assert profile.schema_version == "admissible_native_mission_profile_v3"
    assert profile.is_launchable_runtime_profile is False
    assert profile.claim_authority.authorship.value == "OWNER_AUTHORED"
    assert profile.claim_authority.coverage_status.value == "NOT_ASSESSED"
    assert [claim.claim_id for claim in profile.claim_authority.claims] == [
        "zulu-owner-first", "mike-owner-second", "alpha-owner-third", "tango-owner-fourth"
    ]
    assert profile.claim_authority.claims[0].depends_on == (
        "mike-owner-second", "alpha-owner-third", "tango-owner-fourth"
    )
    assert profile.claim_authority.claims[0].non_claims == (
        "Zulu exclusion", "Mike exclusion", "Alpha exclusion"
    )
    summary = authored.contract_summary
    assert summary["claim_authority"] == profile.claim_authority.to_dict()
    assert summary["claim_review_notices"] == EXPECTED_CLAIM_NOTICES
    review_text = " ".join(summary["claim_review_notices"].values()).lower()
    assert all(term not in review_text for term in FORBIDDEN_REVIEW_CLAIMS)

    clauses = summary["gate_clauses"]
    result_claims = summary["claim_authority"]["claims"]
    assert len(clauses) == 2
    assert len(result_claims) == 4
    assert [clause["clause_id"] for clause in clauses] == [
        f"gate-{'a' * 12}.material", f"gate-{'a' * 12}.git"
    ]
    assert [clause["text"] for clause in clauses] == [
        "Required material paths exist under the assigned workspace.",
        "Exactly one local commit with the required complete message exists.",
    ]
    assert [claim["claim_id"] for claim in result_claims] == [
        "zulu-owner-first", "mike-owner-second", "alpha-owner-third", "tango-owner-fourth"
    ]
    assert [claim["statement"] for claim in result_claims] == [claim["statement"] for claim in claims]
    assert not ({clause["clause_id"] for clause in clauses} & {claim["claim_id"] for claim in result_claims})
    assert all(claim not in clauses for claim in result_claims)
    assert all(clause not in result_claims for clause in clauses)


def test_absent_claims_preserve_v2_and_omit_claim_presentation(tmp_path):
    authored = _author(tmp_path, _owner_input(), "b")
    profile = authored.profile
    assert profile.schema_version == "admissible_native_mission_profile_v2"
    assert profile.is_launchable_runtime_profile is True
    assert set(authored.contract_summary) == V2_SUMMARY_KEYS
    assert "claim_authority" not in authored.contract_summary
    assert "claim_review_notices" not in authored.contract_summary
    assert "runtime_launchable" not in authored.contract_summary
    assert authored.profile_fingerprint == profile.profile_fingerprint
    assert canonical_bytes(profile.to_dict()) == Path(authored.document_path).read_bytes()


def test_claim_free_v2_service_response_has_no_v3_placeholders_and_remains_preparable(tmp_path):
    counter = iter(f"{value:032x}" for value in range(100, 140))
    launcher = ProductLauncher(
        _configuration(tmp_path), verify_head=False, id_generator=lambda: next(counter),
        browser_opener=lambda _url: None,
    )
    launcher.proxy_g2 = lambda method, path, body=None: (
        (200, {"contract_id": "canonical-v2-contract"})
        if path.endswith("/validate") else (599, {})
    )
    try:
        status, body = launcher.author_and_validate(_owner_input())
        assert status == 200
        assert body["contract_summary"]["schema_version"] == "admissible_native_mission_profile_v2"
        assert set(body["contract_summary"]) == V2_SUMMARY_KEYS
        assert "runtime_launchable" not in body
        serialized = json.dumps(body, sort_keys=True, separators=(",", ":"))
        assert "claim_authority" not in serialized
        assert "claim_review_notices" not in serialized
        assert "result_claim" not in serialized
        assert body["profile_fingerprint"] == launcher._contracts[body["contract_id"]].profile_fingerprint
        preparation_status, preparation = launcher.enqueue_preparation(body["contract_id"])
        assert preparation_status == 202
        assert preparation["state"] == "QUEUED"
    finally:
        launcher.close()


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
        status, body = launcher.author_and_validate(_owner_input(result_claims=_ordered_claims()))
        assert status == 200
        assert body["runtime_launchable"] is False
        assert body["contract_summary"]["schema_version"] == "admissible_native_mission_profile_v3"
        service_claims = body["contract_summary"]["claim_authority"]["claims"]
        assert [claim["claim_id"] for claim in service_claims] == [
            "zulu-owner-first", "mike-owner-second", "alpha-owner-third", "tango-owner-fourth"
        ]
        assert service_claims[0]["depends_on"] == [
            "mike-owner-second", "alpha-owner-third", "tango-owner-fourth"
        ]
        assert service_claims[0]["non_claims"] == [
            "Zulu exclusion", "Mike exclusion", "Alpha exclusion"
        ]
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
