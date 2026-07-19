"""Core tests for the Admissible product read model (G4A).

All committed tests use synthetic temporary run roots. No provider, verifier,
checkpoint, server, browser or Node process is ever launched.
"""

from __future__ import annotations

import json

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
    build_material_refusal,
    snapshot,
)


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
    assert detail.product_verdict.source is VerdictSource.CONFLICT
    assert detail.product_verdict.consistent is False
    assert detail.presentation_status is PresentationStatus.INCONSISTENT


def test_unknown_future_verdict_is_unsupported_raw(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    provider = FakeTruthProvider({"product_verdict": "ADMITTED_QUANTUM_2027"})
    detail = load_run_detail(root, truth_provider=provider)
    assert detail.product_verdict.verdict is ProductVerdict.UNSUPPORTED
    assert detail.product_verdict.raw_verdict == "ADMITTED_QUANTUM_2027"
    assert detail.presentation_status is PresentationStatus.UNKNOWN


def test_persisted_product_block_alone_supplies_verdict(tmp_path):
    b = build_full_records(tmp_path / "run")
    b.product_block({"product_verdict": "REFUSED"})
    detail = load_run_detail(tmp_path / "run")
    assert detail.product_verdict.verdict is ProductVerdict.REFUSED
    assert detail.product_verdict.source is VerdictSource.PERSISTED_PRODUCT_BLOCK


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
