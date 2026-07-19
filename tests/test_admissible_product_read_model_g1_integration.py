"""G1 + G4A integration: authoritative reconstruction through the product read model.

Bounded tests only. No real provider, server, browser, behavioral verifier, or
historical checkpoint capture is invoked. Historical roots are read-only smoke.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from admissible.delegated_gate.mission_profile import VerificationMode as G1VerificationMode
from admissible.product_read_model import (
    PresentationStatus,
    ProductVerdict,
    TruthStatus,
    VerdictSource,
    VerificationMode,
    load_run_detail,
    render_result_json,
    render_run_html,
)
from admissible.product_read_model.truth_provider import (
    G1ReconstructionAdapter,
    RunTruthProvider,
    TruthProviderError,
    TruthProviderUnavailable,
    create_g1_reconstruction_provider,
)
from tests.product_read_model.builders import RunRootBuilder, snapshot
from test_admissible_runtime_native_mission import (
    _profile,
    _repository,
    _runtime_harness,
)

HISTORICAL_PARENT = Path(r"C:\Users\stris\Documents\Projets\ENTRE")
HISTORICAL_RUNS = (
    "native-cursor-longrun-001",
    "native-cursor-flagship-002",
    "native-cursor-flagship-003",
)


def _file_manifest(root: Path) -> dict[str, bytes]:
    manifest: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            manifest[str(path.relative_to(root)).replace("\\", "/")] = path.read_bytes()
    return manifest


# --- 8.1 canonical provider construction -------------------------------------


def test_canonical_provider_construction_without_manual_injection():
    provider = create_g1_reconstruction_provider()
    assert isinstance(provider, G1ReconstructionAdapter)
    assert isinstance(provider, RunTruthProvider)
    via_classmethod = G1ReconstructionAdapter.from_canonical_g1()
    assert isinstance(via_classmethod, G1ReconstructionAdapter)
    # Unwired placeholder behaviour is preserved for explicit empty construction.
    with pytest.raises(TruthProviderUnavailable):
        G1ReconstructionAdapter().reconstruct(Path("."))


def test_canonical_provider_construction_is_inert():
    trap = mock.Mock(side_effect=AssertionError("registry lookup is forbidden"))
    with mock.patch("admissible.delegated_gate.native_canary.registered_profiles", trap):
        provider = create_g1_reconstruction_provider()
        assert provider is not None
    trap.assert_not_called()


# --- helpers -----------------------------------------------------------------


def _refused_harness(tmp_path: Path):
    source = _repository(tmp_path / "source")
    profile = _profile(
        source,
        mode=G1VerificationMode.FROZEN_BEHAVIORAL,
        profile_id="g1g4a-refused-v2",
        checkpoint_exit_code=0,
        frozen_source="process.exit(7);",
    )
    return _runtime_harness(tmp_path, profile), profile


def _admitted_observed_harness(tmp_path: Path):
    source = _repository(tmp_path / "source")
    profile = _profile(
        source,
        mode=G1VerificationMode.OBSERVED_ONLY,
        profile_id="g1g4a-observed-v2",
        checkpoint_exit_code=0,
    )
    return _runtime_harness(tmp_path, profile), profile


# --- 8.2 authoritative refusal -----------------------------------------------


def test_authoritative_refusal_through_real_g1_adapter(tmp_path: Path):
    harness, profile = _refused_harness(tmp_path)
    assert harness.outcome.product_verdict == ProductVerdict.REFUSED.value

    # Contradictory persisted claim must not override G1 authority.
    claim_path = harness.evidence / "product-verdict.json"
    claim_path.write_text(
        json.dumps({"product_verdict": "ADMITTED_VERIFIED", "verification_mode": "FROZEN_BEHAVIORAL"}),
        encoding="utf-8",
    )

    provider = create_g1_reconstruction_provider()
    detail = load_run_detail(harness.root, truth_provider=provider)
    pv = detail.product_verdict

    assert pv.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert pv.verdict is ProductVerdict.REFUSED
    assert pv.verdict_is_authoritative is True
    assert pv.truth_status is TruthStatus.AUTHORITATIVE
    assert pv.claimed_verdict is ProductVerdict.ADMITTED_VERIFIED
    assert pv.claim_is_authoritative is False
    assert detail.presentation_status is PresentationStatus.INCONSISTENT
    assert profile.session_id in (detail.identity.session_id, detail.identity.run_id)


# --- 8.3 authoritative observed admission ------------------------------------


def test_authoritative_observed_admission_preserves_g1_verdict_and_mode(tmp_path: Path):
    harness, _profile_obj = _admitted_observed_harness(tmp_path)
    assert harness.outcome.product_verdict == ProductVerdict.ADMITTED_OBSERVED.value
    assert harness.outcome.verification_mode == G1VerificationMode.OBSERVED_ONLY.value

    provider = create_g1_reconstruction_provider()
    detail = load_run_detail(harness.root, truth_provider=provider)
    pv = detail.product_verdict
    summary = detail.summary()

    assert pv.verdict is ProductVerdict.ADMITTED_OBSERVED
    assert pv.verification_mode is VerificationMode.OBSERVED_ONLY
    assert pv.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert pv.truth_status is TruthStatus.AUTHORITATIVE
    assert pv.verdict_is_authoritative is True
    assert detail.presentation_status is PresentationStatus.ADMITTED
    assert summary.product_verdict is ProductVerdict.ADMITTED_OBSERVED
    assert summary.verdict_source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
    assert summary.truth_status is TruthStatus.AUTHORITATIVE

    html = render_run_html(detail)
    payload = render_result_json(detail)
    admission = payload["result_admission_state"]
    assert "ADMITTED_OBSERVED" in html
    assert "authoritative" in html.lower()
    assert admission["verdict"] == "ADMITTED_OBSERVED"
    assert admission["verification_mode"] == "OBSERVED_ONLY"
    assert admission["source"] == "AUTHORITATIVE_RECONSTRUCTION"
    assert "Behavior was not independently verified." in (
        pv.behavioral_non_claim or ""
    )


# --- 8.4 conflicting persisted claim -----------------------------------------


def test_conflicting_persisted_claim_retains_both_values(tmp_path: Path):
    harness, _ = _admitted_observed_harness(tmp_path)
    (harness.evidence / "product-verdict.json").write_text(
        json.dumps({"product_verdict": "REFUSED", "verification_mode": "FROZEN_BEHAVIORAL"}),
        encoding="utf-8",
    )
    provider = create_g1_reconstruction_provider()
    detail = load_run_detail(harness.root, truth_provider=provider)
    pv = detail.product_verdict

    assert pv.verdict is ProductVerdict.ADMITTED_OBSERVED
    assert pv.verdict_is_authoritative is True
    assert pv.claimed_verdict is ProductVerdict.REFUSED
    assert pv.claim_is_authoritative is False
    assert pv.consistent is False
    assert detail.presentation_status is PresentationStatus.INCONSISTENT


# --- 8.5 invalid or incomplete evidence --------------------------------------


def test_invalid_incomplete_evidence_does_not_fabricate_admission(tmp_path: Path):
    root = tmp_path / "incomplete-run"
    builder = RunRootBuilder(root)
    builder.preflight().final_status(status="PRECAPTURE_ELIGIBILITY_FAILED")
    # No delegated session / native stores that G1 can reconstruct.

    provider = create_g1_reconstruction_provider()
    with pytest.raises((TruthProviderUnavailable, TruthProviderError)):
        provider.reconstruct(root)

    detail = load_run_detail(root, truth_provider=provider)
    pv = detail.product_verdict
    assert pv.verdict is ProductVerdict.UNKNOWN
    assert pv.verdict_is_authoritative is False
    assert detail.presentation_status is not PresentationStatus.ADMITTED

    html = render_run_html(detail)
    payload_text = json.dumps(render_result_json(detail))
    # No exception-message leak of evidence contents into presentation.
    assert "hunter2" not in html
    assert "hunter2" not in payload_text
    assert "authoritative G1 reconstruction rejected" not in html
    assert "authoritative G1 reconstruction rejected" not in payload_text


def test_g4a_synthetic_refusal_fixture_is_unavailable_not_admitted(tmp_path: Path):
    """G4A builders alone are not G1-reconstructable runtime-v2 evidence."""

    root = tmp_path / "g4a-synthetic"
    b = RunRootBuilder(root)
    b.preflight().delegated_gate().request().attempt_reserved().process_started()
    b.process_observation().result().eligibility(eligible=False).terminal().final_status()

    provider = create_g1_reconstruction_provider()
    detail = load_run_detail(root, truth_provider=provider)
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert detail.presentation_status is not PresentationStatus.ADMITTED


# --- 8.6 registry independence and non-mutation ------------------------------


def test_registry_independence_and_evidence_non_mutation(tmp_path: Path):
    harness, _ = _refused_harness(tmp_path)
    before = snapshot(harness.root)
    trap = mock.Mock(side_effect=AssertionError("registry lookup is forbidden"))
    provider = create_g1_reconstruction_provider()
    with mock.patch("admissible.delegated_gate.native_canary.registered_profiles", trap):
        detail = load_run_detail(harness.root, truth_provider=provider)
    trap.assert_not_called()
    assert detail.product_verdict.verdict is ProductVerdict.REFUSED
    after = snapshot(harness.root)
    assert after == before
    # Reconstruction must not introduce new lock/cache files under the run root.
    before_locks = {name for name in before if ".lock" in name or name.endswith(".cache")}
    after_locks = {name for name in after if ".lock" in name or name.endswith(".cache")}
    assert after_locks == before_locks


# --- 9 historical smoke ------------------------------------------------------


@pytest.mark.parametrize("run_name", HISTORICAL_RUNS)
def test_historical_smoke_truthful_and_byte_identical(run_name: str):
    root = HISTORICAL_PARENT / run_name
    if not root.is_dir():
        pytest.skip(f"historical run absent: {root}")

    before = _file_manifest(root)
    provider = create_g1_reconstruction_provider()
    # Direct adapter call: either authoritative mapping or a typed seam error.
    try:
        mapping = provider.reconstruct(root)
    except (TruthProviderUnavailable, TruthProviderError) as exc:
        mapping = None
        seam_error = exc
    else:
        seam_error = None

    detail = load_run_detail(root, truth_provider=provider)
    pv = detail.product_verdict

    if mapping is not None:
        # Supported by current G1 contract: preserve exact authority, no false admit from exit 0.
        assert pv.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
        assert pv.truth_status is TruthStatus.AUTHORITATIVE
        assert pv.verdict.value == mapping.get("product_verdict")
        if run_name == "native-cursor-flagship-003":
            assert pv.verdict is not ProductVerdict.ADMITTED_OBSERVED
            assert pv.verdict is not ProductVerdict.ADMITTED_VERIFIED
    else:
        # Structurally unsupported / evidence-invalid under the new G1 contract.
        assert isinstance(seam_error, (TruthProviderUnavailable, TruthProviderError))
        assert pv.verdict is ProductVerdict.UNKNOWN
        assert pv.verdict_is_authoritative is False
        assert detail.presentation_status is not PresentationStatus.ADMITTED
        if run_name == "native-cursor-flagship-003":
            # Exit code 0 must never become admission without G1 authority.
            assert pv.verdict is ProductVerdict.UNKNOWN

    after = _file_manifest(root)
    assert after == before


def test_explicit_injected_adapter_is_not_silently_replaced():
    """Explicit reconstruct_fn injection must keep test-double semantics."""

    sent = {"product_verdict": "REFUSED", "verification_mode": "FROZEN_BEHAVIORAL"}

    def _fake(run_root: Path, **_kwargs: object) -> dict[str, object]:
        assert run_root is not None
        return dict(sent)

    provider = G1ReconstructionAdapter(_fake)
    assert provider.reconstruct(Path(".")) == sent
