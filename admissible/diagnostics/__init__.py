"""Forensic diagnostics for Admissible's callable-backend transport (RUN_046).

This package is a diagnostic instrument only: it is never imported by
``admissible.agent_backend``, ``admissible.high_autonomy_controller``, or any
production code path. It exists to answer "which layer failed" for a real
Cursor CLI invocation -- process lifecycle, buffering, timeout behavior --
with direct evidence instead of guesses.

See docs/admissible-cursor-callable-transport-forensics.md and
benchmark/reports/admissible_cursor_callable_transport_forensic_audit.md.
"""

from __future__ import annotations
