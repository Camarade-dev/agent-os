"""Bounded local-browser runtime verification for Admissible (RUN_043).

This package is a dedicated, read-only runtime verifier with narrowly
defined local side effects. It is not a general executor: it may only
serve an authorized local workspace over a loopback-only HTTP server,
launch an allowlisted installed Chromium-family browser with fixed safe
arguments, dispatch a bounded set of input events, evaluate a strict
declarative verification plan, and collect bounded evidence.

See docs/admissible-bounded-browser-runtime-verification.md for the full
authority and boundary description.
"""

from __future__ import annotations
