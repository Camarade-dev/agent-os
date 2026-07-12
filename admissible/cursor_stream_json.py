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
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

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

CLASSIFICATIONS = frozenset(
    {
        CLASSIFICATION_SUCCESS,
        CLASSIFICATION_EMPTY_SUCCESS,
        CLASSIFICATION_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL,
        CLASSIFICATION_TRANSPORT_PARSE_ERROR,
        CLASSIFICATION_TERMINAL_ERROR,
    }
)

DEFAULT_MALFORMED_LINE_TOLERANCE = 0


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


def _contains_create_plan(events: list[dict[str, Any]]) -> bool:
    for event in events:
        try:
            blob = json.dumps(event, ensure_ascii=False)
        except (TypeError, ValueError):
            continue
        if "createplan" in blob.lower():
            return True
    return False


def parse_cursor_stream_json(
    stdout: str,
    *,
    malformed_line_tolerance: int = DEFAULT_MALFORMED_LINE_TOLERANCE,
) -> StreamJsonParseResult:
    """Parse ``stdout`` as bounded NDJSON and classify the terminal response.

    Never raises: every failure mode is returned as a classified
    ``StreamJsonParseResult`` so the caller can map it to a terminal backend
    status without a try/except around parsing.
    """

    lines = [line for line in stdout.splitlines() if line.strip()]
    events: list[dict[str, Any]] = []
    malformed_count = 0
    for line in lines:
        try:
            parsed = json.loads(line)
        except (ValueError, TypeError):
            malformed_count += 1
            continue
        if not isinstance(parsed, dict):
            malformed_count += 1
            continue
        events.append(parsed)

    if malformed_count > malformed_line_tolerance:
        return StreamJsonParseResult(
            classification=CLASSIFICATION_TRANSPORT_PARSE_ERROR,
            diagnostics={
                "total_line_count": len(lines),
                "malformed_line_count": malformed_count,
                "malformed_line_tolerance": malformed_line_tolerance,
            },
            error_message=(
                f"NDJSON parse error: {malformed_count} malformed line(s) exceed the "
                f"configured tolerance of {malformed_line_tolerance}."
            ),
        )

    event_type_counts: dict[str, int] = {event_type: 0 for event_type in RECOGNIZED_EVENT_TYPES}
    event_type_counts["unrecognized"] = 0
    tool_call_events: list[dict[str, Any]] = []
    interaction_query_events: list[dict[str, Any]] = []
    terminal_events: list[dict[str, Any]] = []
    for event in events:
        event_type = event.get("type")
        if event_type in RECOGNIZED_EVENT_TYPES:
            event_type_counts[event_type] += 1
        else:
            event_type_counts["unrecognized"] += 1
        if event_type == "tool_call":
            tool_call_events.append(event)
        elif event_type == "interaction_query":
            interaction_query_events.append(event)
        elif event_type == "result":
            terminal_events.append(event)

    diagnostics: dict[str, Any] = {
        "total_line_count": len(lines),
        "malformed_line_count": malformed_count,
        "event_type_counts": event_type_counts,
        "tool_call_event_count": len(tool_call_events),
        "interaction_query_event_count": len(interaction_query_events),
        "assistant_event_count": event_type_counts.get("assistant", 0),
        "terminal_event_count": len(terminal_events),
        "create_plan_detected": _contains_create_plan(
            tool_call_events + interaction_query_events
        ),
    }

    if not terminal_events:
        return StreamJsonParseResult(
            classification=CLASSIFICATION_TRANSPORT_PARSE_ERROR,
            diagnostics=diagnostics,
            error_message="No terminal `result` event found in NDJSON output.",
        )
    if len(terminal_events) > 1:
        return StreamJsonParseResult(
            classification=CLASSIFICATION_TRANSPORT_PARSE_ERROR,
            diagnostics=diagnostics,
            error_message=(
                f"Found {len(terminal_events)} terminal `result` events; exactly one "
                "authoritative terminal event is required."
            ),
        )

    terminal = terminal_events[0]
    subtype = terminal.get("subtype")
    is_error = terminal.get("is_error")
    result_value = terminal.get("result")

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
