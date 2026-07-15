"""Admissible V0 Slice 5B — minimal local operator review surface.

This package provides a small, loopback-only web interface through which a
single local operator can inspect a persisted governed V0 run together with its
Slice-5A runtime evidence, and record exactly one durable terminal disposition
(``ACCEPT_RESULT`` / ``REJECT_RESULT``).

It is strictly a *review* surface. It never invokes a model provider, a browser
verifier, an executor, retry, or repair; it never mutates the immutable session,
the runtime result, the generated target, or any evidence artifact. Authoritative
facts are reconstructed exclusively from persisted evidence and are shown with an
explicit integrity classification: evidence that fails its integrity checks is
visibly classified as uncertainty and never silently displayed as trustworthy.
"""

from __future__ import annotations

from admissible.review_surface.disposition_store import (
    ACCEPT_RESULT,
    REJECT_RESULT,
    DispositionConflict,
    DispositionCorrupt,
    DispositionRecord,
    ReviewDispositionStore,
)
from admissible.review_surface.evidence_model import (
    ReviewModel,
    build_review_model,
)
from admissible.review_surface.server import ReviewServer, launch_review_server

__all__ = [
    "ACCEPT_RESULT",
    "REJECT_RESULT",
    "DispositionConflict",
    "DispositionCorrupt",
    "DispositionRecord",
    "ReviewDispositionStore",
    "ReviewModel",
    "build_review_model",
    "ReviewServer",
    "launch_review_server",
]
