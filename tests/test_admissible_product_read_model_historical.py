"""Optional machine-local historical smoke tests.

These load the real persisted historical run roots read-only. They skip cleanly
when the roots are absent (e.g. on CI or another machine) and assert the roots
remain byte-identical after loading.

The historical parent directory is opt-in via ``ADMISSIBLE_HISTORICAL_RUNS_PARENT``
so no machine-specific path is committed. The separate green-run check remains
opt-in via ``ADMISSIBLE_GREEN_RUN_ROOT``.
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
    TruthStatus,
    render_run_html,
)
from admissible.product_read_model import load_run_detail

_HISTORICAL = {
    "native-cursor-longrun-001": FailingBoundary.MATERIAL_ELIGIBILITY,
    "native-cursor-flagship-002": FailingBoundary.BEHAVIORAL_VERIFIER,
    "native-cursor-flagship-003": FailingBoundary.BEHAVIORAL_VERIFIER,
}

_HISTORICAL_PARENT_ENV = "ADMISSIBLE_HISTORICAL_RUNS_PARENT"


def _historical_parent() -> Path | None:
    """Return the opt-in historical parent directory, or ``None`` when unset."""

    raw = os.environ.get(_HISTORICAL_PARENT_ENV)
    if not raw:
        return None
    base = Path(raw)
    return base if base.is_dir() else None


def _manifest(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result[str(path.relative_to(root))] = (path.stat().st_size, digest)
    return result


@pytest.mark.parametrize("run_name,expected_boundary", list(_HISTORICAL.items()))
def test_historical_runs_present_are_refused_and_immutable(run_name, expected_boundary):
    parent = _historical_parent()
    if parent is None:
        pytest.skip(f"historical parent not opted in via {_HISTORICAL_PARENT_ENV}")
    root = parent / run_name
    if not root.is_dir():
        pytest.skip(f"historical root absent: {root}")
    before = _manifest(root)
    detail = load_run_detail(root, truth_provider=LegacyPersistedFactsProvider())

    assert detail.canonical_classification == "PRECAPTURE_ELIGIBILITY_FAILED"
    assert detail.canonical_classification_kind is ClassificationKind.NON_SUCCESS
    assert detail.presentation_status is PresentationStatus.REFUSED
    # No G1 reconstruction: the effective product verdict stays UNKNOWN and is
    # never a false admission, even though a legacy facts provider is supplied.
    assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
    assert detail.product_verdict.verdict_is_authoritative is False
    assert detail.product_verdict.truth_status is TruthStatus.NO_VERDICT
    assert detail.presentation_status is not PresentationStatus.ADMITTED
    assert detail.failing_boundary.boundary is expected_boundary
    # Rendering must not raise and must be self-contained.
    html = render_run_html(detail)
    assert "<iframe" not in html.lower()

    after = _manifest(root)
    assert before == after, "historical root mutated by read-only load"


def test_historical_runs_retain_exact_classifications_and_no_admission():
    """Runs 001/002/003 keep exact canonical classifications and never admit."""

    parent = _historical_parent()
    if parent is None:
        pytest.skip(f"historical parent not opted in via {_HISTORICAL_PARENT_ENV}")
    seen = 0
    for run_name in _HISTORICAL:
        root = parent / run_name
        if not root.is_dir():
            continue
        seen += 1
        before = _manifest(root)
        # Without any provider the effective verdict must remain UNKNOWN.
        detail = load_run_detail(root)
        assert detail.canonical_classification == "PRECAPTURE_ELIGIBILITY_FAILED"
        assert detail.canonical_classification_kind is ClassificationKind.NON_SUCCESS
        assert detail.product_verdict.verdict is ProductVerdict.UNKNOWN
        assert detail.product_verdict.claim_present is False
        assert detail.product_verdict.truth_status is TruthStatus.NOT_CONFIGURED
        assert detail.presentation_status is not PresentationStatus.ADMITTED
        after = _manifest(root)
        assert before == after, f"{run_name} mutated by read-only load"
    if seen == 0:
        pytest.skip("no historical roots present under the opted-in parent")


def test_run_003_display_distinctions_when_present():
    parent = _historical_parent()
    if parent is None:
        pytest.skip(f"historical parent not opted in via {_HISTORICAL_PARENT_ENV}")
    root = parent / "native-cursor-flagship-003"
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
    parent = _historical_parent()
    if parent is None:
        pytest.skip(f"historical parent not opted in via {_HISTORICAL_PARENT_ENV}")
    root = parent / "native-cursor-longrun-001"
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
    assert detail.product_verdict.verdict_is_authoritative is False
    assert detail.presentation_status is not PresentationStatus.ADMITTED
