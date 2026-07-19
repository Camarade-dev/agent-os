"""Admissible product read model (G4A).

A read-only presentation layer over persisted Admissible runs. This lane never
decides whether a run succeeded and is never a reconstruction authority. An
authoritative product verdict is supplied only through the :class:`RunTruthProvider`
seam (future G1 integration) or an explicit persisted product block; otherwise
the product verdict remains ``UNKNOWN``.

Public API:

* discovery: :func:`discover_runs`, :func:`load_run_root`
* loading:   :func:`load_run_detail`, :func:`load_run_summary`
* rendering: :func:`render_result_json`, :func:`render_run_html`
* seam:      :class:`RunTruthProvider`, :class:`FakeTruthProvider`,
             :class:`LegacyPersistedFactsProvider`, :class:`G1ReconstructionAdapter`
"""

from __future__ import annotations

from . import enums, evidence_reader, presentation_types
from .discovery import (
    DiscoveredRun,
    RunConflict,
    RunDiscoveryResult,
    discover_runs,
    load_run_root,
)
from .enums import (
    ClassificationKind,
    CompletenessState,
    ExecutionState,
    FailingBoundary,
    HumanDisposition,
    OutcomeState,
    PresentationStatus,
    PresenceState,
    ProductVerdict,
    VerdictSource,
    VerificationMode,
)
from .presentation_types import (
    ArtifactView,
    AuthorizationView,
    BehavioralVerificationView,
    CheckpointView,
    DiagnosticExcerpt,
    EvidenceCompletenessView,
    EvidenceTimelineEntry,
    FailingBoundaryView,
    HumanDispositionView,
    MaterialView,
    ProcessView,
    ProductVerdictView,
    RunDetail,
    RunIdentityView,
    RunSummary,
    WorkspaceGitView,
)
from .product_extractor import CANONICAL_BEHAVIORAL_NON_CLAIM, extract_product_verdict
from .read_model import load_run_detail, load_run_summary
from .renderer import render_result_json, render_run_html
from .truth_provider import (
    FakeTruthProvider,
    G1ReconstructionAdapter,
    LegacyPersistedFactsProvider,
    RaisingTruthProvider,
    RunTruthProvider,
    TruthProviderError,
    TruthProviderUnavailable,
)

__all__ = [
    "enums",
    "evidence_reader",
    "presentation_types",
    # discovery
    "DiscoveredRun",
    "RunConflict",
    "RunDiscoveryResult",
    "discover_runs",
    "load_run_root",
    # enums
    "ClassificationKind",
    "CompletenessState",
    "ExecutionState",
    "FailingBoundary",
    "HumanDisposition",
    "OutcomeState",
    "PresentationStatus",
    "PresenceState",
    "ProductVerdict",
    "VerdictSource",
    "VerificationMode",
    # presentation types
    "ArtifactView",
    "AuthorizationView",
    "BehavioralVerificationView",
    "CheckpointView",
    "DiagnosticExcerpt",
    "EvidenceCompletenessView",
    "EvidenceTimelineEntry",
    "FailingBoundaryView",
    "HumanDispositionView",
    "MaterialView",
    "ProcessView",
    "ProductVerdictView",
    "RunDetail",
    "RunIdentityView",
    "RunSummary",
    "WorkspaceGitView",
    # extractor
    "CANONICAL_BEHAVIORAL_NON_CLAIM",
    "extract_product_verdict",
    # loading
    "load_run_detail",
    "load_run_summary",
    # rendering
    "render_result_json",
    "render_run_html",
    # seam
    "FakeTruthProvider",
    "G1ReconstructionAdapter",
    "LegacyPersistedFactsProvider",
    "RaisingTruthProvider",
    "RunTruthProvider",
    "TruthProviderError",
    "TruthProviderUnavailable",
]
