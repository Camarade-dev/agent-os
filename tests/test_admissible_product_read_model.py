"""Core tests for the Admissible product read model (G4A).

All committed tests use synthetic temporary run roots. No provider, verifier,
checkpoint, server, browser or Node process is ever launched.
"""

from __future__ import annotations

import json
import re

import pytest

from admissible.product_read_model import (
    ClassificationKind,
    CompletenessState,
    ExecutionState,
    FailingBoundary,
    FakeTruthProvider,
    HumanDisposition,
    LegacyPersistedFactsProvider,
    OutcomeState,
    PresentationStatus,
    PresenceState,
    ProductVerdict,
    RaisingTruthProvider,
    TruthProviderOutcome,
    TruthStatus,
    VerdictSource,
    VerificationMode,
    extract_product_verdict,
    load_run_detail,
    load_run_summary,
    render_result_json,
    render_run_html,
)
from admissible.product_read_model.product_extractor import CANONICAL_BEHAVIORAL_NON_CLAIM
from tests.product_read_model.builders import (
    RunRootBuilder,
    build_behavioral_refusal,
    build_full_records,
    build_incomplete_refusal,
    build_material_refusal,
    snapshot,
)


def _badge_class_for_role(html_text: str, role: str) -> tuple[str | None, str | None]:
    """Extract (badge-kind, text) for a top-level badge with the given data-role.

    Semantic (not substring) probe: returns ``(None, None)`` when no badge with
    that role is present.
    """

    match = re.search(
        r'<span class="badge badge-([a-z]+)"[^>]*data-role="'
        + re.escape(role)
        + r'"[^>]*>([^<]*)</span>',
        html_text,
    )
    if not match:
        return None, None
    return match.group(1), match.group(2)


# --- refusal scenarios -------------------------------------------------------


def test_refused_before_behavioral_verification(tmp_path):
    root = build_material_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    assert detail.material.result is OutcomeState.FAILED
    assert detail.behavioral.result is OutcomeState.ABSENT
    assert detail.checkpoint.result is OutcomeState.ABSENT
    assert detail.failing_boundary.boundary is FailingBoundary.MATERIAL_ELIGIBILITY
    assert "required_material_paths_missing" in detail.failing_boundary.reasons
    assert detail.presentation_status is PresentationStatus.REFUSED
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN


def test_refused_after_behavioral_verification(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    assert detail.material.result is OutcomeState.PASSED
    assert detail.behavioral.result is OutcomeState.FAILED
    assert detail.behavioral.exit_code == 1
    assert detail.failing_boundary.boundary is FailingBoundary.BEHAVIORAL_VERIFIER
    assert detail.presentation_status is PresentationStatus.REFUSED


def test_provider_exit_zero_plus_verifier_failure_is_not_success(tmp_path):
    """The run-003 shape: exit 0, material pass, verifier fail, checkpoint absent."""

    root = build_behavioral_refusal(tmp_path / "run", provider_exit=0)
    detail = load_run_detail(root)
    assert detail.process.execution_state is ExecutionState.COMPLETED
    assert detail.process.exit_code == 0
    assert detail.material.result is OutcomeState.PASSED
    assert detail.behavioral.result is OutcomeState.FAILED
    assert detail.checkpoint.result is OutcomeState.ABSENT
    assert detail.canonical_classification == "PRECAPTURE_ELIGIBILITY_FAILED"
    assert detail.canonical_classification_kind is ClassificationKind.NON_SUCCESS
    # Never called successful.
    assert detail.presentation_status is not PresentationStatus.ADMITTED
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    # The JSON result and HTML must not claim admission either.
    result = render_result_json(detail)
    assert result["result_admission_state"]["verdict"] == "UNKNOWN"
    html = render_run_html(detail)
    assert "presentation: REFUSED" in html
    assert "product verdict: UNKNOWN" in html


# --- authoritative verdicts --------------------------------------------------


def test_verified_authoritative_verdict(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"})
    detail = load_run_detail(root, truth_provider=provider)
    assert detail.product_verdict.verdict is ProductVerdict.ADMITTED_VERIFIED
    assert detail.product_verdict.verification_mode is VerificationMode.FROZEN_BEHAVIORAL
    assert detail.product_verdict.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert detail.presentation_status is PresentationStatus.ADMITTED


def test_observed_authoritative_verdict_carries_non_claim(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_OBSERVED", "verification_mode": "OBSERVED_ONLY"})
    detail = load_run_detail(root, truth_provider=provider)
    assert detail.product_verdict.verdict is ProductVerdict.ADMITTED_OBSERVED
    assert detail.product_verdict.behavioral_non_claim == CANONICAL_BEHAVIORAL_NON_CLAIM
    assert detail.presentation_status is PresentationStatus.ADMITTED


def test_missing_authoritative_verdict_stays_unknown(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root, truth_provider=LegacyPersistedFactsProvider())
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert detail.product_verdict.source is VerdictSource.NONE


def test_green_canary_without_authoritative_verdict_is_unknown(tmp_path):
    """A SUCCESS canary classification does not imply product admission."""

    b = build_full_records(tmp_path / "run")
    b.final_status(status="CHECKPOINT_CAPTURED_CANARY_SUCCESS", detail="ok", canary_success=True)
    detail = load_run_detail(tmp_path / "run")
    assert detail.canonical_classification_kind is ClassificationKind.SUCCESS
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert detail.presentation_status is PresentationStatus.UNKNOWN


# --- conflicting / unknown verdicts ------------------------------------------


def test_conflicting_product_verdict_is_inconsistent(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "REFUSED"})
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_VERIFIED"})
    detail = load_run_detail(tmp_path / "run", truth_provider=provider)
    pv = detail.product_verdict
    # The authoritative verdict wins as the effective verdict; the contradicting
    # persisted claim is retained and flags inconsistency (never erases it).
    assert pv.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert pv.verdict is ProductVerdict.ADMITTED_VERIFIED
    assert pv.claimed_verdict is ProductVerdict.REFUSED
    assert pv.consistent is False
    assert detail.presentation_status is PresentationStatus.INCONSISTENT


def test_unknown_future_verdict_is_unsupported_raw(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_QUANTUM_2027"})
    detail = load_run_detail(root, truth_provider=provider)
    assert detail.product_verdict.verdict is ProductVerdict.UNSUPPORTED
    assert detail.product_verdict.raw_verdict == "ADMITTED_QUANTUM_2027"
    assert detail.presentation_status is PresentationStatus.UNKNOWN


def test_persisted_product_block_alone_is_unverified_claim(tmp_path):
    """A persisted product block WITHOUT a provider is an unverified claim only."""

    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "REFUSED"})
    detail = load_run_detail(tmp_path / "run")
    pv = detail.product_verdict
    # The persisted block never becomes the effective authoritative verdict.
    assert pv.verdict is ProductVerdict.UNKNOWN
    assert pv.source is VerdictSource.NONE
    assert pv.truth_status is TruthStatus.NOT_CONFIGURED
    assert pv.verdict_is_authoritative is False
    # It is retained, verbatim, as an unverified claim.
    assert pv.claim_present is True
    assert pv.claimed_verdict is ProductVerdict.REFUSED
    assert pv.claim_is_authoritative is False


# --- absent / missing evidence -----------------------------------------------


def test_missing_final_status_is_incomplete(tmp_path):
    b = RunRootBuilder(tmp_path / "run")
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation().result().eligibility(eligible=True).behavioral().terminal()
    # deliberately no final_status
    detail = load_run_detail(tmp_path / "run")
    assert detail.identity.final_status_presence is PresenceState.ABSENT
    assert detail.presentation_status is PresentationStatus.INCOMPLETE


def test_missing_process_result_absent(tmp_path):
    root = build_material_refusal(tmp_path / "run")  # this shape has no result
    detail = load_run_detail(root)
    # result record absent, but process observation present -> still COMPLETED
    assert detail.workspace_git.present in (PresenceState.PRESENT, PresenceState.ABSENT)
    assert detail.process.execution_state is ExecutionState.COMPLETED


def test_absent_verifier_is_not_passed(tmp_path):
    root = build_material_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    assert detail.behavioral.present is PresenceState.ABSENT
    assert detail.behavioral.result is OutcomeState.ABSENT
    assert detail.behavioral.result is not OutcomeState.PASSED


def test_absent_checkpoint_is_not_failed(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    assert detail.checkpoint.attempted is False
    assert detail.checkpoint.result is OutcomeState.ABSENT
    assert detail.checkpoint.result is not OutcomeState.FAILED


# --- truth provider failure --------------------------------------------------


def test_truth_provider_failure_is_surfaced_not_fatal(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root, truth_provider=RaisingTruthProvider())
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert any("truth provider failed" in note for note in detail.read_notes)


def test_truth_provider_returning_non_mapping_is_handled(tmp_path):
    class BadProvider:
        def reconstruct(self, run_root):  # noqa: ANN001
            return ["not", "a", "mapping"]

    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root, truth_provider=BadProvider())
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert any("non-mapping" in note for note in detail.read_notes)


# --- human disposition -------------------------------------------------------


def test_human_disposition_absent_and_present(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    assert detail.human_disposition.disposition is HumanDisposition.NONE

    b = build_full_records(tmp_path / "run2")
    b.delegated_gate(human_disposition="ACCEPTED", human_boundary_reason="owner accepted")
    detail2 = load_run_detail(tmp_path / "run2")
    assert detail2.human_disposition.disposition is HumanDisposition.ACCEPTED
    assert detail2.human_disposition.reason == "owner accepted"


# --- rendering ---------------------------------------------------------------


def test_result_json_is_serializable_and_layered(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    result = render_result_json(detail)
    # Round-trips as JSON.
    text = json.dumps(result)
    assert "PRECAPTURE_ELIGIBILITY_FAILED" in text
    # Layers are explicitly separate.
    assert result["execution_state"]["provider_exit_code"] == 0
    assert result["result_admission_state"]["verdict"] == "UNKNOWN"
    assert result["behavioral_verifier_result"]["result"] == "FAILED"
    assert result["checkpoint_result"]["result"] == "ABSENT"


def test_html_escapes_persisted_strings(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.final_status(detail="<script>alert('xss')</script> & \"danger\"")
    detail = load_run_detail(tmp_path / "run")
    html = render_run_html(detail)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;" in html
    assert "<iframe" not in html.lower()
    assert "http://" not in html and "https://" not in html


def test_full_detail_json_roundtrips(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    text = json.dumps(detail.to_json())
    assert json.loads(text)["presentation_status"] == "REFUSED"


def test_summary_projection_matches_detail(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    summary = load_run_summary(root)
    assert summary.presentation_status is detail.presentation_status
    assert summary.canonical_classification == detail.canonical_classification
    assert summary.failing_boundary is detail.failing_boundary.boundary


# --- diagnostics -------------------------------------------------------------


def test_diagnostic_truncation_marker(tmp_path):
    b = RunRootBuilder(tmp_path / "run")
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).result(exit_code=0).eligibility(eligible=True)
    b.behavioral(exit_code=1, stderr_text=b"X" * 100_000).terminal().final_status()
    detail = load_run_detail(tmp_path / "run", excerpt_bytes=256)
    stderr_excerpts = [d for d in detail.diagnostics if "stderr" in d.label]
    assert stderr_excerpts, "expected a behavioral stderr excerpt"
    excerpt = stderr_excerpts[0]
    assert excerpt.truncated is True
    assert len(excerpt.excerpt.encode("utf-8")) <= 256
    html = render_run_html(detail)
    assert "excerpt truncated" in html


# --- timeline ----------------------------------------------------------------


def test_timeline_is_deterministic_and_ordered(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    d1 = load_run_detail(root)
    d2 = load_run_detail(root)
    keys1 = [e.event_key for e in d1.timeline]
    keys2 = [e.event_key for e in d2.timeline]
    assert keys1 == keys2
    # canonical order includes these logical events
    assert keys1[:3] == ["authorization_materialized", "attempt_reserved", "process_started"]
    assert not any(e.out_of_order for e in d1.timeline)


def test_timeline_flags_conflicting_timestamp(tmp_path):
    b = build_full_records(tmp_path / "run")
    # Make the terminal record's created_at precede attempt reservation.
    b.terminal()
    import json as _json
    terminal_path = next((tmp_path / "run" / "evidence" / "native-execution").glob("*native-terminal.json"))
    data = _json.loads(terminal_path.read_text())
    data["created_at"] = "2020-01-01T00:00:00.000000Z"
    terminal_path.write_text(_json.dumps(data), encoding="utf-8")
    detail = load_run_detail(tmp_path / "run")
    terminal_entry = next(e for e in detail.timeline if e.event_key == "terminal_status_persisted")
    assert terminal_entry.out_of_order is True


# --- extractor unit ----------------------------------------------------------


def test_extractor_tolerates_nested_product_block():
    view = extract_product_verdict({"product": {"verdict": "ADMITTED_OBSERVED", "mode": "OBSERVED_ONLY"}}, None)
    assert view.verdict is ProductVerdict.ADMITTED_OBSERVED
    assert view.verification_mode is VerificationMode.OBSERVED_ONLY


def test_extractor_none_none_is_unknown():
    view = extract_product_verdict(None, None)
    assert view.verdict is ProductVerdict.UNKNOWN
    assert view.source is VerdictSource.NONE
    assert view.consistent is True


def test_extractor_agreeing_sources_are_consistent():
    view = extract_product_verdict({"product_verdict": "REFUSED"}, {"product_verdict": "REFUSED"})
    assert view.consistent is True
    assert view.verdict is ProductVerdict.REFUSED
    assert view.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION


def test_extractor_persisted_only_is_never_effective():
    """A persisted-only claim (no provider) never sets the effective verdict."""

    view = extract_product_verdict(
        None, {"product_verdict": "ADMITTED_VERIFIED"}, outcome=TruthProviderOutcome.NOT_CONFIGURED
    )
    assert view.verdict is ProductVerdict.UNKNOWN
    assert view.source is VerdictSource.NONE
    assert view.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED
    assert view.claim_is_authoritative is False


def test_extractor_full_authority_matrix():
    """Every row of the section-5 authority matrix, probed at the boundary."""

    admitted = {"product_verdict": "ADMITTED_VERIFIED"}
    refused = {"product_verdict": "REFUSED"}
    out = TruthProviderOutcome

    # absent auth, absent claim -> UNKNOWN, unknown
    v = extract_product_verdict(None, None, outcome=out.NOT_CONFIGURED)
    assert v.verdict is ProductVerdict.UNKNOWN
    assert v.truth_status is TruthStatus.NOT_CONFIGURED
    assert v.consistent is True

    # absent auth, ADMITTED claim -> UNKNOWN, unverified claim (NOT inconsistent)
    v = extract_product_verdict(None, admitted, outcome=out.NOT_CONFIGURED)
    assert v.verdict is ProductVerdict.UNKNOWN
    assert v.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED
    assert v.consistent is True

    # error, ADMITTED claim -> UNKNOWN, inconsistent/unavailable
    v = extract_product_verdict(None, admitted, outcome=out.RAISED)
    assert v.verdict is ProductVerdict.UNKNOWN
    assert v.truth_status is TruthStatus.ERROR
    assert v.consistent is False

    # unavailable, ADMITTED claim -> UNKNOWN, inconsistent/unavailable
    v = extract_product_verdict(None, admitted, outcome=out.RETURNED_INVALID)
    assert v.verdict is ProductVerdict.UNKNOWN
    assert v.truth_status is TruthStatus.UNAVAILABLE
    assert v.consistent is False

    # REFUSED auth, absent claim -> REFUSED, authoritative
    v = extract_product_verdict(refused, None, outcome=out.RETURNED_MAPPING)
    assert v.verdict is ProductVerdict.REFUSED
    assert v.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert v.consistent is True

    # REFUSED auth, REFUSED claim -> REFUSED, authoritative, consistent
    v = extract_product_verdict(refused, refused, outcome=out.RETURNED_MAPPING)
    assert v.verdict is ProductVerdict.REFUSED
    assert v.consistent is True

    # REFUSED auth, ADMITTED claim -> REFUSED, inconsistent
    v = extract_product_verdict(refused, admitted, outcome=out.RETURNED_MAPPING)
    assert v.verdict is ProductVerdict.REFUSED
    assert v.consistent is False
    assert v.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED

    # ADMITTED auth, absent claim -> ADMITTED, authoritative
    v = extract_product_verdict(admitted, None, outcome=out.RETURNED_MAPPING)
    assert v.verdict is ProductVerdict.ADMITTED_VERIFIED
    assert v.verdict_is_authoritative is True

    # ADMITTED auth, ADMITTED claim -> ADMITTED, authoritative, consistent
    v = extract_product_verdict(admitted, admitted, outcome=out.RETURNED_MAPPING)
    assert v.verdict is ProductVerdict.ADMITTED_VERIFIED
    assert v.consistent is True

    # ADMITTED auth, REFUSED claim -> ADMITTED, inconsistent
    v = extract_product_verdict(admitted, refused, outcome=out.RETURNED_MAPPING)
    assert v.verdict is ProductVerdict.ADMITTED_VERIFIED
    assert v.consistent is False
    assert v.claimed_verdict is ProductVerdict.REFUSED


# --- adversarial authority repair (G4A cold-audit blockers) ------------------


def test_10_1_persisted_admission_claim_without_provider(tmp_path):
    b = build_incomplete_refusal(tmp_path / "run")
    b.product_block({"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"})
    detail = load_run_detail(tmp_path / "run")  # no truth provider
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.UNKNOWN
    assert pv.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED
    assert pv.claim_is_authoritative is False
    assert pv.truth_status is TruthStatus.NOT_CONFIGURED
    assert detail.canonical_classification == "PRECAPTURE_ELIGIBILITY_FAILED"
    assert detail.presentation_status is not PresentationStatus.ADMITTED
    # Summary keeps the source/authority distinction.
    summary = detail.summary()
    assert summary.product_verdict is ProductVerdict.UNKNOWN
    assert summary.claimed_product_verdict is ProductVerdict.ADMITTED_VERIFIED
    assert summary.verdict_is_authoritative is False
    assert summary.verdict_source is VerdictSource.NONE
    # HTML shows no authoritative admitted badge.
    html = render_run_html(detail)
    kind, _ = _badge_class_for_role(html, "authoritative-verdict")
    assert kind != "ok"
    claim_kind, claim_text = _badge_class_for_role(html, "persisted-claim")
    assert claim_kind is not None and claim_kind != "ok"
    assert "UNVERIFIED" in claim_text


def test_10_2_provider_failure_plus_persisted_admission_claim(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "ADMITTED_VERIFIED"})
    detail = load_run_detail(tmp_path / "run", truth_provider=RaisingTruthProvider())
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.UNKNOWN
    assert pv.truth_status is TruthStatus.ERROR
    assert pv.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED
    assert pv.claim_is_authoritative is False
    assert detail.presentation_status is PresentationStatus.INCONSISTENT
    assert detail.presentation_status is not PresentationStatus.ADMITTED
    # Bounded diagnostic; no traceback / message leak.
    assert any("truth provider failed" in n for n in detail.read_notes)


def test_10_2b_provider_invalid_plus_persisted_admission_claim(tmp_path):
    class BadProvider:
        def reconstruct(self, run_root):  # noqa: ANN001
            return ["not", "a", "mapping"]

    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "ADMITTED_VERIFIED"})
    detail = load_run_detail(tmp_path / "run", truth_provider=BadProvider())
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.UNKNOWN
    assert pv.truth_status is TruthStatus.UNAVAILABLE
    assert detail.presentation_status is not PresentationStatus.ADMITTED


def test_10_3_authoritative_refusal_vs_persisted_admission(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "ADMITTED_VERIFIED"})
    provider = FakeTruthProvider({"product_verdict": "REFUSED"})
    detail = load_run_detail(tmp_path / "run", truth_provider=provider)
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.REFUSED
    assert pv.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert pv.consistent is False
    assert pv.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED  # both retained
    assert detail.presentation_status is PresentationStatus.INCONSISTENT


def test_10_4_authoritative_admission_vs_persisted_refusal(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "REFUSED"})
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"})
    detail = load_run_detail(tmp_path / "run", truth_provider=provider)
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.ADMITTED_VERIFIED  # authoritative admission retained
    assert pv.verdict_is_authoritative is True
    assert pv.consistent is False
    assert pv.claimed_verdict is ProductVerdict.REFUSED  # both retained
    assert detail.presentation_status is PresentationStatus.INCONSISTENT
    # Presentation is inconsistent rather than silently green.
    html = render_run_html(detail)
    pres_kind, _ = _badge_class_for_role(html, "presentation-status")
    assert pres_kind != "ok"


def test_10_5_matching_authoritative_and_persisted(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"})
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"})
    detail = load_run_detail(tmp_path / "run", truth_provider=provider)
    pv = detail.product_verdict
    assert pv.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert pv.consistent is True
    assert pv.verdict is ProductVerdict.ADMITTED_VERIFIED
    assert detail.presentation_status is PresentationStatus.ADMITTED
    html = render_run_html(detail)
    kind, _ = _badge_class_for_role(html, "authoritative-verdict")
    assert kind == "ok"


def test_10_6_no_provider_no_claim(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    detail = load_run_detail(root)
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.UNKNOWN
    assert pv.claim_present is False
    assert pv.claimed_verdict is ProductVerdict.UNKNOWN
    assert pv.source is VerdictSource.NONE
    assert pv.truth_status is TruthStatus.NOT_CONFIGURED
    assert detail.presentation_status is not PresentationStatus.ADMITTED
    summary = detail.summary()
    assert summary.verdict_source is VerdictSource.NONE
    assert summary.claimed_product_verdict is ProductVerdict.UNKNOWN


def test_10_7_summary_serialization_distinguishes_states(tmp_path):
    admitted = {"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"}

    # (a) authoritative admission
    build_full_records(tmp_path / "a")
    ja = load_run_detail(tmp_path / "a", truth_provider=FakeTruthProvider(admitted)).summary().to_json()
    assert ja["product_verdict"] == "ADMITTED_VERIFIED"
    assert ja["verdict_is_authoritative"] is True
    assert ja["truth_status"] == "AUTHORITATIVE"

    # (b) unverified persisted claim (no provider)
    bb = build_full_records(tmp_path / "b")
    bb.product_block({"product_verdict": "ADMITTED_VERIFIED"})
    jb = load_run_detail(tmp_path / "b").summary().to_json()
    assert jb["product_verdict"] == "UNKNOWN"
    assert jb["verdict_is_authoritative"] is False
    assert jb["claimed_product_verdict"] == "ADMITTED_VERIFIED"
    assert jb["truth_status"] == "NOT_CONFIGURED"

    # (c) provider unavailable (raises) with the same persisted claim
    jc = load_run_detail(tmp_path / "b", truth_provider=RaisingTruthProvider()).summary().to_json()
    assert jc["product_verdict"] == "UNKNOWN"
    assert jc["truth_status"] == "ERROR"
    assert jc["claimed_product_verdict"] == "ADMITTED_VERIFIED"

    # (d) conflict: authoritative refusal vs persisted admission
    jd = load_run_detail(tmp_path / "b", truth_provider=FakeTruthProvider({"product_verdict": "REFUSED"})).summary().to_json()
    assert jd["product_verdict"] == "REFUSED"
    assert jd["verdict_consistent"] is False
    assert jd["claimed_product_verdict"] == "ADMITTED_VERIFIED"

    # The four serializations are mutually distinguishable.
    blobs = {json.dumps(x, sort_keys=True) for x in (ja, jb, jc, jd)}
    assert len(blobs) == 4


def test_10_8_html_badges_are_authority_semantic(tmp_path):
    admitted = {"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"}

    # Authoritative admitted -> green authoritative-verdict badge, no claim badge.
    build_full_records(tmp_path / "a")
    da = load_run_detail(tmp_path / "a", truth_provider=FakeTruthProvider(admitted))
    ha = render_run_html(da)
    assert _badge_class_for_role(ha, "authoritative-verdict")[0] == "ok"
    assert _badge_class_for_role(ha, "persisted-claim")[0] is None

    # Persisted-only admission claim -> NO admitted badge; explicit UNVERIFIED claim.
    bb = build_full_records(tmp_path / "b")
    bb.product_block({"product_verdict": "ADMITTED_VERIFIED"})
    db = load_run_detail(tmp_path / "b")
    hb = render_run_html(db)
    assert _badge_class_for_role(hb, "authoritative-verdict")[0] != "ok"
    claim_kind, claim_text = _badge_class_for_role(hb, "persisted-claim")
    assert claim_kind is not None and claim_kind != "ok"
    assert "UNVERIFIED" in claim_text

    # Provider failure -> non-admitted presentation and verdict badges.
    dc = load_run_detail(tmp_path / "b", truth_provider=RaisingTruthProvider())
    hc = render_run_html(dc)
    assert _badge_class_for_role(hc, "presentation-status")[0] != "ok"
    assert _badge_class_for_role(hc, "authoritative-verdict")[0] != "ok"


def test_persisted_claim_raw_value_is_escaped(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "<script>alert(1)</script>"})
    detail = load_run_detail(tmp_path / "run")
    pv = detail.product_verdict
    assert pv.claimed_verdict is ProductVerdict.UNSUPPORTED
    assert pv.raw_claimed_verdict == "<script>alert(1)</script>"
    html = render_run_html(detail)
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html
