"""Optional machine-local historical smoke tests.

These load the real persisted historical run roots read-only. They skip cleanly
when the roots are absent (e.g. on CI or another machine) and assert the roots
remain byte-identical after loading. The green-run check is opt-in via an
environment variable so no green machine path is hard-coded here.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from admissible.product_read_model import (
    ClassificationKind,
    FailingBoundary,
    LegacyPersistedFactsProvider,
    OutcomeState,
    PresentationStatus,
    ProductVerdict,
    load_run_detail,
    render_run_html,
)

_HISTORICAL = {
    "native-cursor-longrun-001": FailingBoundary.MATERIAL_ELIGIBILITY,
    "native-cursor-flagship-002": FailingBoundary.BEHAVIORAL_VERIFIER,
    "native-cursor-flagship-003": FailingBoundary.BEHAVIORAL_VERIFIER,
}
_BASE = Path(r"C:\Users\stris\Documents\Projets\ENTRE")


def _manifest(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result[str(path.relative_to(root))] = (path.stat().st_size, digest)
    return result


@pytest.mark.parametrize("run_name,expected_boundary", list(_HISTORICAL.items()))
def test_historical_runs_present_are_refused_and_immutable(run_name, expected_boundary):
    root = _BASE / run_name
    if not root.is_dir():
        pytest.skip(f"historical root absent: {root}")
    before = _manifest(root)
    detail = load_run_detail(root, truth_provider=LegacyPersistedFactsProvider())

    assert detail.canonical_classification == "PRECAPTURE_ELIGIBILITY_FAILED"
    assert detail.canonical_classification_kind is ClassificationKind.NON_SUCCESS
    assert detail.presentation_status is PresentationStatus.REFUSED
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert detail.failing_boundary.boundary is expected_boundary
    # Rendering must not raise and must be self-contained.
    html = render_run_html(detail)
    assert "<iframe" not in html.lower()

    after = _manifest(root)
    assert before == after, "historical root mutated by read-only load"


def test_run_003_display_distinctions_when_present():
    root = _BASE / "native-cursor-flagship-003"
    if not root.is_dir():
        pytest.skip(f"historical root absent: {root}")
    detail = load_run_detail(root)
    assert detail.process.exit_code == 0
    assert detail.material.result is OutcomeState.PASSED
    assert detail.behavioral.result is OutcomeState.FAILED
    assert detail.checkpoint.result is OutcomeState.ABSENT
    # Exit 0 + verifier fail is never presented as admitted.
    assert detail.presentation_status is not PresentationStatus.ADMITTED


def test_run_001_material_failure_before_verifier_when_present():
    root = _BASE / "native-cursor-longrun-001"
    if not root.is_dir():
        pytest.skip(f"historical root absent: {root}")
    detail = load_run_detail(root)
    assert detail.material.result is OutcomeState.FAILED
    assert detail.behavioral.result is OutcomeState.ABSENT
    assert detail.checkpoint.result is OutcomeState.ABSENT


def test_optional_green_run_is_not_auto_admitted():
    """A discoverable green run stays UNKNOWN at the product layer without a verdict.

    Opt-in via ADMISSIBLE_GREEN_RUN_ROOT so no green machine path is committed.
    """

    green = os.environ.get("ADMISSIBLE_GREEN_RUN_ROOT")
    if not green or not Path(green).is_dir():
        pytest.skip("no green run root supplied via ADMISSIBLE_GREEN_RUN_ROOT")
    detail = load_run_detail(green, truth_provider=LegacyPersistedFactsProvider())
    # Without an authoritative verdict, product admission is never inferred.
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert detail.presentation_status is not PresentationStatus.ADMITTED
