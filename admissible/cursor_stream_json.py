"""Cursor CLI ``--output-format stream-json`` NDJSON parsing (slice
ADMISSIBLE_NARROW_FIX_CURSOR_ONESHOT_STREAM_JSON_ASK_AND_OPERATION_LIMIT).

Parses the bounded line-delimited JSON stream produced by a real
``cursor-agent --print --output-format stream-json --stream-partial-output
--mode ask`` invocation and identifies the single authoritative terminal
response. This module never calls a provider, never executes anything, and
never mutates a workspace -- it is pure text-in/structured-result-out parsing.

Canonical live evidence (see the task this slice implements) showed that a
real Ask/plan-mode turn can complete "successfully" at the transport level
(exit 0, valid NDJSON, exactly one terminal ``result`` event) while never
producing a usable textual proposal -- the model instead drove Cursor's own
``createPlan`` tool/interaction-query workflow and the terminal text was only
progress narration. Naively treating that as an ordinary successful response
would silently hand a plan payload to the operation extractor. This module
keeps that distinction explicit: a valid-but-substance-free terminal event is
its own classification (``terminal_result_without_structured_proposal``), not
``empty_success`` and not silently promoted to ``success``.

Recognized event ``type`` values (at minimum): ``system``, ``user``,
``thinking``, ``assistant``, ``tool_call``, ``interaction_query``, ``result``.
Only ``terminal_event.result`` -- the single authoritative ``type == "result"``
event with ``subtype == "success"``, ``is_error == false``, and a non-empty
string ``result`` -- is ever treated as the canonical agent response.
Assistant/thinking/tool/interaction-query events are retained only as bounded
diagnostic counts, never concatenated into the canonical response and never
scanned for executable operations.

Slice ADMISSIBLE_NARROW_FIX_CURSOR_NDJSON_TERMINAL_EVENT_CAPTURE fixed a proven
live defect: a real Cursor NDJSON stream can be substantially larger than the
managed-process in-memory diagnostic-capture limit (thinking/assistant/tool
events before the terminal result), and a *prefix-only* capture can discard
the authoritative terminal event simply because it arrives last. This module's
:class:`IncrementalStreamJsonAccumulator` is fed one line at a time as the
process streams output (via ``admissible.managed_process``'s ``on_stdout_line``
hook) so the terminal event, its canonical result text, and every diagnostic
count stay accurate *independent of* whether the raw diagnostic capture itself
was truncated. ``parse_cursor_stream_json`` (whole-string) is now a thin
wrapper over the same accumulator for callers that only ever see the full
string (e.g. the legacy injected-runner test seam).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from admissible.governed_run import DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES
from admissible.long_run_envelope_builder import STRUCTURED_OPERATION_MARKER

RECOGNIZED_EVENT_TYPES = frozenset(
    {
        "system",
        "user",
        "thinking",
        "assistant",
        "tool_call",
        "interaction_query",
        "result",
    }
)

# -- classification outcomes --------------------------------------------------
CLASSIFICATION_SUCCESS = "success"
CLASSIFICATION_EMPTY_SUCCESS = "empty_success"
CLASSIFICATION_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL = (
    "terminal_result_without_structured_proposal"
)
CLASSIFICATION_TRANSPORT_PARSE_ERROR = "transport_parse_error"
CLASSIFICATION_TERMINAL_ERROR = "terminal_error"
# The terminal event could not be preserved because a hard transport safety
# limit was exceeded -- either raw capture was truncated before any terminal
# event was seen, or the terminal event's own `result` text exceeded its
# dedicated safety limit. Distinct from CLASSIFICATION_TRANSPORT_PARSE_ERROR
# ("no terminal event found" with nothing indicating why) so an operator can
# tell a capture-limit artifact apart from a genuinely malformed/absent
# response.
CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED = "transport_output_truncated"

CLASSIFICATIONS = frozenset(
    {
        CLASSIFICATION_SUCCESS,
        CLASSIFICATION_EMPTY_SUCCESS,
        CLASSIFICATION_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL,
        CLASSIFICATION_TRANSPORT_PARSE_ERROR,
        CLASSIFICATION_TERMINAL_ERROR,
        CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED,
    }
)

DEFAULT_MALFORMED_LINE_TOLERANCE = 0

# Separate bounded ceiling for the canonical terminal `result` text alone (not
# the whole raw NDJSON stream). Must comfortably fit the existing admitted
# write-byte policy (admissible.governed_run.DEFAULT_MAX_TOTAL_PROPOSED_WRITE_
# BYTES, 256 KiB of write content across one response's operations) plus
# JSON-string-escaping overhead (quotes/newlines can roughly double size) and
# the ADMISSIBLE_STRUCTURED_OPERATION markers/narrative text around it -- while
# still being a bounded ceiling, not "accept anything". A `result` string
# larger than this is never silently truncated and accepted as a partial
# proposal; it fails closed (CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED).
DEFAULT_MAX_CANONICAL_RESULT_BYTES = max(4 * DEFAULT_MAX_TOTAL_PROPOSED_WRITE_BYTES, 1024 * 1024)


@dataclass
class StreamJsonParseResult:
    """Structured outcome of parsing one NDJSON stdout capture."""

    classification: str
    canonical_response: str | None = None
    terminal_event: dict[str, Any] | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None

    @property
    def ok(self) -> bool:
        return self.classification == CLASSIFICATION_SUCCESS and bool(
            (self.canonical_response or "").strip()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "canonical_response": self.canonical_response,
            "terminal_event": self.terminal_event,
            "diagnostics": dict(self.diagnostics),
            "error_message": self.error_message,
        }


def _event_mentions_create_plan(event: dict[str, Any]) -> bool:
    try:
        blob = json.dumps(event, ensure_ascii=False)
    except (TypeError, ValueError):
        return False
    return "createplan" in blob.lower()


class IncrementalStreamJsonAccumulator:
    """Feed one NDJSON line at a time; classify the terminal response once
    the stream ends.

    Every count and the terminal event itself are tracked as each line is
    read, so they are accurate *even when the raw diagnostic capture that
    fed this accumulator was itself bounded/truncated* -- this is what lets
    the terminal `result` event survive being the last thing written after a
    stream far larger than any prefix-only capture limit
    (ADMISSIBLE_NARROW_FIX_CURSOR_NDJSON_TERMINAL_EVENT_CAPTURE). Memory use
    stays O(1) beyond a handful of counters: only the first terminal event is
    ever stored, and its `result` text is dropped (not retained) the moment
    it is found to exceed ``max_canonical_result_bytes``.
    """

    def __init__(
        self,
        *,
        malformed_line_tolerance: int = DEFAULT_MALFORMED_LINE_TOLERANCE,
        max_canonical_result_bytes: int = DEFAULT_MAX_CANONICAL_RESULT_BYTES,
    ) -> None:
        self._malformed_line_tolerance = malformed_line_tolerance
        self._max_canonical_result_bytes = max_canonical_result_bytes
        self._total_line_count = 0
        self._malformed_line_count = 0
        self._event_type_counts: dict[str, int] = {t: 0 for t in RECOGNIZED_EVENT_TYPES}
        self._event_type_counts["unrecognized"] = 0
        self._tool_call_count = 0
        self._interaction_query_count = 0
        self._create_plan_detected = False
        self._terminal_event_count = 0
        self._terminal_event: dict[str, Any] | None = None
        self._canonical_result_exceeds_limit = False

    def feed_line(self, line: str) -> None:
        """Observe one raw stdout line. Never raises."""
        text = line.strip()
        if not text:
            return
        self._total_line_count += 1
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            self._malformed_line_count += 1
            return
        if not isinstance(parsed, dict):
            self._malformed_line_count += 1
            return

        event_type = parsed.get("type")
        if event_type in RECOGNIZED_EVENT_TYPES:
            self._event_type_counts[event_type] += 1
        else:
            self._event_type_counts["unrecognized"] += 1

        if event_type == "tool_call":
            self._tool_call_count += 1
            if _event_mentions_create_plan(parsed):
                self._create_plan_detected = True
        elif event_type == "interaction_query":
            self._interaction_query_count += 1
            if _event_mentions_create_plan(parsed):
                self._create_plan_detected = True
        elif event_type == "result":
            self._terminal_event_count += 1
            if self._terminal_event_count == 1:
                self._store_terminal_event(parsed)

    def _store_terminal_event(self, event: dict[str, Any]) -> None:
        result_value = event.get("result")
        if (
            isinstance(result_value, str)
            and len(result_value.encode("utf-8", errors="replace"))
            > self._max_canonical_result_bytes
        ):
            # Fail closed: never retain (and never let a caller silently
            # accept) a partial canonical result. The non-text fields are
            # still enough to prove terminal success/failure.
            self._canonical_result_exceeds_limit = True
            self._terminal_event = {k: v for k, v in event.items() if k != "result"}
        else:
            self._terminal_event = dict(event)

    def _diagnostics(self, *, raw_output_truncated: bool) -> dict[str, Any]:
        return {
            "total_line_count": self._total_line_count,
            "malformed_line_count": self._malformed_line_count,
            "event_type_counts": dict(self._event_type_counts),
            "tool_call_event_count": self._tool_call_count,
            "interaction_query_event_count": self._interaction_query_count,
            "assistant_event_count": self._event_type_counts.get("assistant", 0),
            "terminal_event_count": self._terminal_event_count,
            "create_plan_detected": self._create_plan_detected,
            "raw_output_truncated": raw_output_truncated,
            "canonical_result_exceeds_limit": self._canonical_result_exceeds_limit,
            "max_canonical_result_bytes": self._max_canonical_result_bytes,
        }

    def finalize(self, *, raw_output_truncated: bool = False) -> StreamJsonParseResult:
        """Classify the accumulated stream. Never raises."""
        diagnostics = self._diagnostics(raw_output_truncated=raw_output_truncated)

        if self._malformed_line_count > self._malformed_line_tolerance:
            return StreamJsonParseResult(
                classification=CLASSIFICATION_TRANSPORT_PARSE_ERROR,
                diagnostics=diagnostics,
                error_message=(
                    f"NDJSON parse error: {self._malformed_line_count} malformed line(s) "
                    f"exceed the configured tolerance of {self._malformed_line_tolerance}."
                ),
            )

        if self._terminal_event_count == 0:
            if raw_output_truncated:
                return StreamJsonParseResult(
                    classification=CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED,
                    diagnostics=diagnostics,
                    error_message=(
                        "No terminal `result` event was observed, and the managed "
                        "process's raw stdout capture was truncated by its safety "
                        "limit -- terminal success/failure cannot be proven. This is "
                        "a capture-limit artifact, not a malformed response."
                    ),
                )
            return StreamJsonParseResult(
                classification=CLASSIFICATION_TRANSPORT_PARSE_ERROR,
                diagnostics=diagnostics,
                error_message="No terminal `result` event found in NDJSON output.",
            )
        if self._terminal_event_count > 1:
            return StreamJsonParseResult(
                classification=CLASSIFICATION_TRANSPORT_PARSE_ERROR,
                diagnostics=diagnostics,
                error_message=(
                    f"Found {self._terminal_event_count} terminal `result` events; "
                    "exactly one authoritative terminal event is required."
                ),
            )

        terminal = self._terminal_event or {}
        subtype = terminal.get("subtype")
        is_error = terminal.get("is_error")

        if is_error or subtype != "success":
            return StreamJsonParseResult(
                classification=CLASSIFICATION_TERMINAL_ERROR,
                terminal_event=terminal,
                diagnostics=diagnostics,
                error_message=(
                    f"Terminal `result` event reported failure (subtype={subtype!r}, "
                    f"is_error={is_error!r})."
                ),
            )

        if self._canonical_result_exceeds_limit:
            return StreamJsonParseResult(
                classification=CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED,
                terminal_event=terminal,
                diagnostics=diagnostics,
                error_message=(
                    "Terminal `result` event succeeded but its `result` string "
                    f"exceeds the canonical-result safety limit of "
                    f"{self._max_canonical_result_bytes} byte(s); refusing to "
                    "silently accept a partial terminal result."
                ),
            )

        result_value = terminal.get("result")
        if not isinstance(result_value, str) or not result_value.strip():
            return StreamJsonParseResult(
                classification=CLASSIFICATION_EMPTY_SUCCESS,
                terminal_event=terminal,
                diagnostics=diagnostics,
                error_message=(
                    "Terminal `result` event succeeded but its `result` string was empty."
                ),
            )

        if STRUCTURED_OPERATION_MARKER.lower() not in result_value.lower():
            return StreamJsonParseResult(
                classification=CLASSIFICATION_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL,
                canonical_response=result_value,
                terminal_event=terminal,
                diagnostics=diagnostics,
                error_message=(
                    "Terminal `result` event succeeded but contained no "
                    f"{STRUCTURED_OPERATION_MARKER!r} block; refusing to treat progress-only "
                    "or internal planning-tool text as a structured proposal."
                ),
            )

        return StreamJsonParseResult(
            classification=CLASSIFICATION_SUCCESS,
            canonical_response=result_value,
            terminal_event=terminal,
            diagnostics=diagnostics,
        )


def parse_cursor_stream_json(
    stdout: str,
    *,
    malformed_line_tolerance: int = DEFAULT_MALFORMED_LINE_TOLERANCE,
    max_canonical_result_bytes: int = DEFAULT_MAX_CANONICAL_RESULT_BYTES,
    raw_output_truncated: bool = False,
) -> StreamJsonParseResult:
    """Parse a whole (already-fully-captured) NDJSON string and classify the
    terminal response.

    This is a thin wrapper over :class:`IncrementalStreamJsonAccumulator` for
    callers that only ever see the complete string at once (e.g. the legacy
    injected-runner test seam, where no real process is spawned so there is
    nothing to stream). Production Cursor invocations should instead feed the
    accumulator directly via ``on_stdout_line`` while the process runs, since
    a whole string handed to this function may itself already be a truncated
    capture -- pass ``raw_output_truncated=True`` in that case so a missing
    terminal event is classified as a capture-limit artifact rather than a
    generic parse error.

    Never raises: every failure mode is returned as a classified
    ``StreamJsonParseResult`` so the caller can map it to a terminal backend
    status without a try/except around parsing.
    """
    accumulator = IncrementalStreamJsonAccumulator(
        malformed_line_tolerance=malformed_line_tolerance,
        max_canonical_result_bytes=max_canonical_result_bytes,
    )
    for line in stdout.splitlines():
        accumulator.feed_line(line)
    return accumulator.finalize(raw_output_truncated=raw_output_truncated)
