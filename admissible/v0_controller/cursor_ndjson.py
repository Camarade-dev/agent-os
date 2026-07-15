"""Bounded incremental NDJSON observation for the V0 Cursor callable backend.

The Cursor CLI's ``--output-format stream-json`` stdout is line-delimited JSON.
This module consumes it one line at a time *as the process streams*, so the
single authoritative terminal event survives even when the raw diagnostic
capture is truncated by its retention cap: the accumulator keeps O(1) state plus
the first terminal event, never a copy of the stream.

Authority rules encoded here:

- exactly one ``type == "result"`` event with ``subtype == "success"`` and
  ``is_error == false`` is the *only* authoritative terminal success;
- duplicate terminal success rejects; terminal failure rejects; exit without a
  terminal event rejects;
- individual malformed or unrecognized lines are retained only as bounded
  diagnostic counts -- they can never become operations;
- a canonical ``result`` string larger than its dedicated limit is dropped, not
  truncated, and fails closed.

This module is deliberately isolated from the legacy stream-json parser: it has
no notion of legacy structured-operation markers and no legacy imports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

RECOGNIZED_EVENT_TYPES = frozenset(
    {"system", "user", "thinking", "assistant", "tool_call", "interaction_query", "result"}
)

TERMINAL_SUCCESS = "terminal_success"
TERMINAL_FAILURE = "terminal_failure"
TERMINAL_MISSING = "terminal_missing"
TERMINAL_DUPLICATE = "terminal_duplicate"
TERMINAL_MALFORMED = "terminal_malformed"
TERMINAL_CANONICAL_TOO_LARGE = "terminal_canonical_too_large"

DEFAULT_MALFORMED_LINE_TOLERANCE = 0
DEFAULT_MAX_CANONICAL_RESULT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class NdjsonObservation:
    """Bounded, typed outcome of observing one Cursor NDJSON stdout stream."""

    classification: str
    canonical_result: str | None = None
    terminal_event: dict[str, Any] | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    message: str | None = None

    @property
    def ok(self) -> bool:
        return self.classification == TERMINAL_SUCCESS and bool((self.canonical_result or "").strip())

    def diagnostic_facts(self) -> tuple[str, ...]:
        """Flatten the counts into bounded ``key:value`` diagnostic strings."""

        facts: list[str] = [f"ndjson_classification:{self.classification}"]
        for key in sorted(self.diagnostics):
            value = self.diagnostics[key]
            if isinstance(value, dict):
                for sub in sorted(value):
                    facts.append(f"ndjson_{key}.{sub}:{value[sub]}")
            else:
                facts.append(f"ndjson_{key}:{value}")
        return tuple(facts)


class IncrementalNdjsonAccumulator:
    """Feed one raw stdout line at a time; classify once the stream ends."""

    def __init__(
        self,
        *,
        malformed_line_tolerance: int = DEFAULT_MALFORMED_LINE_TOLERANCE,
        max_canonical_result_bytes: int = DEFAULT_MAX_CANONICAL_RESULT_BYTES,
    ) -> None:
        self._malformed_line_tolerance = malformed_line_tolerance
        self._max_canonical_result_bytes = max_canonical_result_bytes
        self._total_lines = 0
        self._malformed_lines = 0
        self._event_counts: dict[str, int] = {name: 0 for name in RECOGNIZED_EVENT_TYPES}
        self._event_counts["unrecognized"] = 0
        self._observed_bytes = 0
        self._terminal_count = 0
        self._terminal_event: dict[str, Any] | None = None
        self._canonical_too_large = False

    @property
    def observed_bytes(self) -> int:
        return self._observed_bytes

    def feed_line(self, line: str) -> None:
        """Observe one raw stdout line.  Never raises."""

        self._observed_bytes += len(line.encode("utf-8", errors="replace"))
        text = line.strip()
        if not text:
            return
        self._total_lines += 1
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            self._malformed_lines += 1
            return
        if not isinstance(parsed, dict):
            self._malformed_lines += 1
            return
        event_type = parsed.get("type")
        if event_type in RECOGNIZED_EVENT_TYPES:
            self._event_counts[event_type] += 1
        else:
            self._event_counts["unrecognized"] += 1
        if event_type == "result":
            self._terminal_count += 1
            if self._terminal_count == 1:
                self._store_terminal(parsed)

    def _store_terminal(self, event: dict[str, Any]) -> None:
        result_value = event.get("result")
        if (
            isinstance(result_value, str)
            and len(result_value.encode("utf-8", errors="replace")) > self._max_canonical_result_bytes
        ):
            # Fail closed: a partial canonical result must never look valid.
            self._canonical_too_large = True
            self._terminal_event = {key: value for key, value in event.items() if key != "result"}
            return
        self._terminal_event = dict(event)

    def _diagnostics(self, *, raw_capture_truncated: bool) -> dict[str, Any]:
        return {
            "total_line_count": self._total_lines,
            "malformed_line_count": self._malformed_lines,
            "event_type_counts": dict(self._event_counts),
            "terminal_event_count": self._terminal_count,
            "observed_stdout_bytes": self._observed_bytes,
            "raw_capture_truncated": raw_capture_truncated,
            "canonical_result_exceeds_limit": self._canonical_too_large,
            "max_canonical_result_bytes": self._max_canonical_result_bytes,
        }

    def finalize(self, *, raw_capture_truncated: bool = False) -> NdjsonObservation:
        """Classify the observed stream.  Never raises."""

        diagnostics = self._diagnostics(raw_capture_truncated=raw_capture_truncated)

        if self._terminal_count > 1:
            return NdjsonObservation(
                TERMINAL_DUPLICATE,
                terminal_event=self._terminal_event,
                diagnostics=diagnostics,
                message=(
                    f"Observed {self._terminal_count} terminal `result` events; "
                    "exactly one authoritative terminal event is required."
                ),
            )
        if self._malformed_lines > self._malformed_line_tolerance:
            return NdjsonObservation(
                TERMINAL_MALFORMED,
                diagnostics=diagnostics,
                message=(
                    f"{self._malformed_lines} malformed NDJSON line(s) exceed the configured "
                    f"tolerance of {self._malformed_line_tolerance}."
                ),
            )
        if self._terminal_count == 0:
            return NdjsonObservation(
                TERMINAL_MISSING,
                diagnostics=diagnostics,
                message=(
                    "The process exited without an authoritative terminal `result` event"
                    + (" (raw capture was truncated)." if raw_capture_truncated else ".")
                ),
            )

        terminal = self._terminal_event or {}
        subtype = terminal.get("subtype")
        is_error = terminal.get("is_error")
        if is_error or subtype != "success":
            return NdjsonObservation(
                TERMINAL_FAILURE,
                terminal_event=terminal,
                diagnostics=diagnostics,
                message=f"Terminal `result` event reported failure (subtype={subtype!r}, is_error={is_error!r}).",
            )
        if self._canonical_too_large:
            return NdjsonObservation(
                TERMINAL_CANONICAL_TOO_LARGE,
                terminal_event=terminal,
                diagnostics=diagnostics,
                message=(
                    "Terminal `result` succeeded but its canonical text exceeds the "
                    f"{self._max_canonical_result_bytes}-byte limit; refusing to truncate it "
                    "into a valid-looking proposal."
                ),
            )
        result_value = terminal.get("result")
        if not isinstance(result_value, str) or not result_value.strip():
            return NdjsonObservation(
                TERMINAL_MALFORMED,
                terminal_event=terminal,
                diagnostics=diagnostics,
                message="Terminal `result` event succeeded with an empty or non-string `result`.",
            )
        return NdjsonObservation(
            TERMINAL_SUCCESS,
            canonical_result=result_value,
            terminal_event=terminal,
            diagnostics=diagnostics,
        )


__all__ = [
    "DEFAULT_MALFORMED_LINE_TOLERANCE",
    "DEFAULT_MAX_CANONICAL_RESULT_BYTES",
    "IncrementalNdjsonAccumulator",
    "NdjsonObservation",
    "RECOGNIZED_EVENT_TYPES",
    "TERMINAL_CANONICAL_TOO_LARGE",
    "TERMINAL_DUPLICATE",
    "TERMINAL_FAILURE",
    "TERMINAL_MALFORMED",
    "TERMINAL_MISSING",
    "TERMINAL_SUCCESS",
]
