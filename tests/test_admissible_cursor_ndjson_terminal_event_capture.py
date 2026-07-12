"""Tests for ADMISSIBLE_NARROW_FIX_CURSOR_NDJSON_TERMINAL_EVENT_CAPTURE.

Proven live failure this slice fixes: a real Cursor one-shot invocation
produced stdout of ~524253 bytes (`output_truncated == true` against the
~512 KiB managed-process capture limit), and the NDJSON parser reported
"No terminal result event found in NDJSON output." because the authoritative
terminal `result` event -- always the *last* line Cursor writes -- fell past
the bounded prefix-only capture.

Covers, at three layers:

1. ``admissible.managed_process`` -- the real ``_StreamPump``/``ManagedProcess``
   now expose ``on_stdout_line`` (every line, live, independent of the bounded
   retention cap) and report a true (non-frozen) total ``stdout_bytes``.
2. ``admissible.cursor_stream_json`` -- ``IncrementalStreamJsonAccumulator``
   classifies from lines fed live, so the terminal event / canonical result /
   diagnostic counts survive raw-capture truncation. New classification
   ``transport_output_truncated`` distinguishes a capture-limit artifact from
   a genuinely malformed/absent response.
3. ``admissible.agent_backend`` -- ``CursorCliAgentBackend``'s managed one-shot
   path wires the accumulator through ``on_stdout_line`` and classifies from
   it instead of re-parsing the bounded ``stdout`` capture.

No real Cursor Agent CLI or provider call anywhere in this file.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from admissible.cursor_stream_json import (
    CLASSIFICATION_SUCCESS,
    CLASSIFICATION_TERMINAL_ERROR,
    CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED,
    CLASSIFICATION_TRANSPORT_PARSE_ERROR,
    IncrementalStreamJsonAccumulator,
    parse_cursor_stream_json,
)
from admissible.long_run_envelope_builder import extract_structured_operation_blocks
from admissible.managed_process import (
    ContainmentStrategy,
    ManagedOneshotResult,
    ManagedProcessResult,
    TreeTerminationOutcome,
    run_managed_oneshot,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "admissible"
    / "cursor_ndjson_terminal_event_capture_fixtures.json"
)

DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024

FOUR_OP_RESULT_TEXT = (
    "ADMISSIBLE_STRUCTURED_OPERATION:\n"
    '{"operation": "write_file", "path": "src/entities.js", "content": "// entities"}\n'
    "ADMISSIBLE_STRUCTURED_OPERATION:\n"
    '{"operation": "write_file", "path": "src/render.js", "content": "// render"}\n'
    "ADMISSIBLE_STRUCTURED_OPERATION:\n"
    '{"operation": "write_file", "path": "src/bots.js", "content": "// bots"}\n'
    "ADMISSIBLE_STRUCTURED_OPERATION:\n"
    '{"operation": "write_file", "path": "src/game.js", "content": "// game"}\n'
    "Status: PROPOSED -- awaiting the bounded execution gate."
)


def _terminal_line(*, result: str, subtype: str = "success", is_error: bool = False) -> str:
    return json.dumps(
        {"type": "result", "subtype": subtype, "is_error": is_error, "result": result}
    )


def _filler_lines_at_least(min_bytes: int) -> list[str]:
    """Deterministic system/user/thinking/assistant/tool_call diagnostic lines
    totalling at least ``min_bytes`` -- larger than the ~512 KiB managed-
    process capture limit by default in these tests."""
    lines = [
        json.dumps({"type": "system", "subtype": "init", "session_id": "sanitized-session"}),
        json.dumps(
            {
                "type": "user",
                "text": "Read the governed instruction and propose bounded write operations.",
            }
        ),
    ]
    total = sum(len(line.encode("utf-8")) + 1 for line in lines)
    i = 0
    event_types = ("thinking", "assistant", "tool_call")
    while total < min_bytes:
        kind = event_types[i % len(event_types)]
        if kind == "tool_call":
            event: dict[str, Any] = {
                "type": "tool_call",
                "tool_call": {"readFileToolCall": {"path": f"file_{i}.txt"}},
                "status": "completed",
            }
        else:
            event = {"type": kind, "text": f"diagnostic filler chunk {i} " + ("x" * 400)}
        line = json.dumps(event)
        lines.append(line)
        total += len(line.encode("utf-8")) + 1
        i += 1
    return lines


def _large_ndjson_lines(min_diagnostic_bytes: int = 600 * 1024) -> list[str]:
    """A synthetic NDJSON stream larger than the 512 KiB capture limit, with
    exactly four structured operations only inside the final terminal event."""
    lines = _filler_lines_at_least(min_diagnostic_bytes)
    lines.append(_terminal_line(result=FOUR_OP_RESULT_TEXT))
    return lines


class _LineStream:
    """Minimal stdout-shaped stream: readline() yields queued lines, then ''."""

    def __init__(self, lines: list[str]) -> None:
        self._iter = iter(line + "\n" for line in lines)
        self.closed = False

    def readline(self) -> str:
        return next(self._iter, "")

    def close(self) -> None:
        self.closed = True


class _FakeStdin:
    def write(self, text: str) -> None:
        pass

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class _FakeCleanProc:
    """A process that has already produced all its output and exits cleanly
    the instant it is waited on -- models a real completed Cursor invocation
    without spawning anything."""

    def __init__(self, lines: list[str]) -> None:
        self.pid = 424242
        self.stdin = _FakeStdin()
        self.stdout = _LineStream(lines)
        self.stderr = _LineStream([])
        self._exited = False

    def poll(self):
        return 0 if self._exited else None

    def wait(self, timeout=None):
        self._exited = True
        return 0

    def kill(self) -> None:
        self._exited = True


class _FakeContainment(ContainmentStrategy):
    name = "fake_test_containment"

    def assign(self, proc) -> None:
        pass

    def observed_descendant_ids(self, proc) -> list[int]:
        return []

    def terminate_tree(self, proc, *, grace_seconds, force_seconds) -> TreeTerminationOutcome:
        return TreeTerminationOutcome(strategy=self.name)

    def is_alive(self, pid) -> bool:
        return False


def _load_fixtures() -> dict:
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Layer 1: admissible.managed_process -- real _StreamPump/ManagedProcess
# ---------------------------------------------------------------------------


class TestManagedProcessOnStdoutLineHook(unittest.TestCase):
    def test_on_stdout_line_observes_every_line_past_the_retention_cap(self) -> None:
        lines = _large_ndjson_lines()
        joined_bytes = sum(len(line.encode("utf-8")) + 1 for line in lines)
        self.assertGreater(joined_bytes, DEFAULT_MAX_CAPTURE_BYTES)

        seen: list[str] = []
        proc = _FakeCleanProc(lines)
        result = run_managed_oneshot(
            ["fake-cursor-agent"],
            cwd=".",
            env={},
            timeout_seconds=5.0,
            spawn=lambda argv, **kw: proc,
            containment=_FakeContainment(),
            on_stdout_line=seen.append,
        )

        # The raw bounded capture reproduces the original bug: the terminal
        # event, written last, falls past the ~512 KiB prefix.
        self.assertTrue(result.process_result.output_truncated)
        self.assertNotIn('"type": "result"', result.stdout)

        # But the live callback saw the complete stream, terminal event
        # included, regardless of the retention cap.
        seen_non_blank = [line for line in seen if line.strip()]
        self.assertEqual(len(seen_non_blank), len(lines))
        terminal_seen = [
            json.loads(line) for line in seen_non_blank if json.loads(line).get("type") == "result"
        ]
        self.assertEqual(len(terminal_seen), 1)
        self.assertEqual(terminal_seen[0]["result"], FOUR_OP_RESULT_TEXT)

    def test_total_stdout_byte_count_is_not_frozen_at_the_capture_cap(self) -> None:
        # Regression: the pre-fix pump stopped incrementing byte_count once
        # the cap was hit, so a stream far larger than the cap still reported
        # a byte count sitting right at the cap boundary.
        lines = _filler_lines_at_least(DEFAULT_MAX_CAPTURE_BYTES + 200 * 1024)
        true_total = sum(len(line.encode("utf-8")) + 1 for line in lines)
        proc = _FakeCleanProc(lines)
        result = run_managed_oneshot(
            ["fake-cursor-agent"],
            cwd=".",
            env={},
            timeout_seconds=5.0,
            spawn=lambda argv, **kw: proc,
            containment=_FakeContainment(),
        )
        self.assertTrue(result.process_result.output_truncated)
        self.assertEqual(result.process_result.stdout_bytes, true_total)
        self.assertGreater(result.process_result.stdout_bytes, DEFAULT_MAX_CAPTURE_BYTES)
        # The retained/diagnostic prefix itself must still be bounded.
        self.assertLessEqual(len(result.stdout.encode("utf-8")), DEFAULT_MAX_CAPTURE_BYTES)

    def test_small_stream_is_unaffected_no_truncation(self) -> None:
        lines = [
            json.dumps({"type": "system", "subtype": "init"}),
            _terminal_line(result=FOUR_OP_RESULT_TEXT),
        ]
        proc = _FakeCleanProc(lines)
        result = run_managed_oneshot(
            ["fake-cursor-agent"],
            cwd=".",
            env={},
            timeout_seconds=5.0,
            spawn=lambda argv, **kw: proc,
            containment=_FakeContainment(),
        )
        self.assertFalse(result.process_result.output_truncated)
        self.assertIn('"type": "result"', result.stdout)


# ---------------------------------------------------------------------------
# Layer 2: admissible.cursor_stream_json -- IncrementalStreamJsonAccumulator
# ---------------------------------------------------------------------------


class TestIncrementalAccumulatorLargeStreams(unittest.TestCase):
    def test_terminal_event_survives_a_stream_larger_than_the_diagnostic_limit(self) -> None:
        lines = _large_ndjson_lines()
        total_bytes = sum(len(line.encode("utf-8")) + 1 for line in lines)
        self.assertGreater(total_bytes, DEFAULT_MAX_CAPTURE_BYTES)

        accumulator = IncrementalStreamJsonAccumulator()
        for line in lines:
            accumulator.feed_line(line)
        # Raw diagnostic capture WAS truncated by the managed-process limit,
        # but the terminal event was independently preserved -- must still
        # succeed, not be misreported as a capture-limit failure.
        result = accumulator.finalize(raw_output_truncated=True)

        self.assertEqual(result.classification, CLASSIFICATION_SUCCESS)
        self.assertEqual(result.diagnostics["terminal_event_count"], 1)
        self.assertTrue(result.diagnostics["raw_output_truncated"])
        blocks = extract_structured_operation_blocks(result.canonical_response)
        operations = [op for block in blocks for op in block["operations"]]
        self.assertEqual(len(operations), 4)
        # No duplicated content from assistant/thinking deltas.
        self.assertEqual(result.canonical_response.count("ADMISSIBLE_STRUCTURED_OPERATION:"), 4)

    def test_canonical_result_larger_than_its_own_limit_fails_closed(self) -> None:
        oversized_result = "ADMISSIBLE_STRUCTURED_OPERATION:\n" + ("y" * 500)
        accumulator = IncrementalStreamJsonAccumulator(max_canonical_result_bytes=64)
        accumulator.feed_line(_terminal_line(result=oversized_result))
        result = accumulator.finalize(raw_output_truncated=False)

        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED)
        self.assertTrue(result.diagnostics["canonical_result_exceeds_limit"])
        self.assertIsNone(result.canonical_response)
        # Success/failure fields (minus the oversized text) are still proven.
        self.assertEqual(result.terminal_event.get("subtype"), "success")
        self.assertNotIn("result", result.terminal_event)

    def test_physically_truncated_final_line_is_malformed_not_output_truncated(self) -> None:
        accumulator = IncrementalStreamJsonAccumulator()
        accumulator.feed_line(json.dumps({"type": "assistant", "text": "still working..."}))
        accumulator.feed_line('{"type": "result", "subtype": "succ')  # cut mid-line
        # Even if the raw capture is *also* reported truncated, a malformed
        # line is a distinct, more specific failure than "ran out of budget".
        result = accumulator.finalize(raw_output_truncated=True)
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)
        self.assertEqual(result.diagnostics["malformed_line_count"], 1)

    def test_no_terminal_event_distinguishes_truncation_from_plain_absence(self) -> None:
        lines = [json.dumps({"type": "assistant", "text": "no terminal event follows"})]

        no_truncation = IncrementalStreamJsonAccumulator()
        for line in lines:
            no_truncation.feed_line(line)
        result_plain = no_truncation.finalize(raw_output_truncated=False)
        self.assertEqual(result_plain.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)
        self.assertIn("No terminal", result_plain.error_message)

        with_truncation = IncrementalStreamJsonAccumulator()
        for line in lines:
            with_truncation.feed_line(line)
        result_truncated = with_truncation.finalize(raw_output_truncated=True)
        self.assertEqual(result_truncated.classification, CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED)
        self.assertIn("capture-limit", (result_truncated.error_message or "").lower())

    def test_terminal_error_found_after_more_than_512kib(self) -> None:
        lines = _filler_lines_at_least(600 * 1024)
        lines.append(_terminal_line(result="", subtype="error", is_error=True))
        accumulator = IncrementalStreamJsonAccumulator()
        for line in lines:
            accumulator.feed_line(line)
        result = accumulator.finalize(raw_output_truncated=True)
        self.assertEqual(result.classification, CLASSIFICATION_TERMINAL_ERROR)

    def test_multiple_terminal_events_still_detected_across_a_large_stream(self) -> None:
        lines = _filler_lines_at_least(300 * 1024)
        lines.append(_terminal_line(result="a"))
        lines.append(_terminal_line(result="b"))
        accumulator = IncrementalStreamJsonAccumulator()
        for line in lines:
            accumulator.feed_line(line)
        result = accumulator.finalize(raw_output_truncated=False)
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)
        self.assertEqual(result.diagnostics["terminal_event_count"], 2)

    def test_parse_cursor_stream_json_whole_string_wrapper_accepts_truncation_flag(self) -> None:
        # The legacy whole-string entrypoint still works and now accepts an
        # explicit truncation flag from the caller.
        stdout = json.dumps({"type": "assistant", "text": "partial"})
        result = parse_cursor_stream_json(stdout, raw_output_truncated=True)
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED)
        result_default = parse_cursor_stream_json(stdout)
        self.assertEqual(result_default.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)


# ---------------------------------------------------------------------------
# Live-failure replay: sanitized cli-005 metadata
# ---------------------------------------------------------------------------


class TestCli005LiveFailureReplay(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _load_fixtures()["cli_005_live_failure_replay"]

    def test_corrected_classification_is_transport_output_truncated(self) -> None:
        # No raw bytes are available for a sanitized real invocation -- the
        # accumulator saw zero terminal events, mirroring the live failure's
        # "no terminal result event found" outcome, but now driven by the
        # recorded `output_truncated` fact rather than treated as generic
        # malformed/parse-error noise.
        accumulator = IncrementalStreamJsonAccumulator()
        result = accumulator.finalize(raw_output_truncated=self.fixture["output_truncated"])
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_OUTPUT_TRUNCATED)
        self.assertNotEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)
        self.assertNotEqual(result.classification, "malformed")

    def test_old_behavior_without_truncation_awareness_was_a_generic_parse_error(self) -> None:
        # Documents the pre-fix behavior this slice corrects: calling the
        # whole-string parser with no truncation signal (the old call site)
        # on the same "no terminal event" shape produced the generic,
        # unhelpful transport_parse_error classification.
        result = parse_cursor_stream_json("")
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)

    def test_fixture_metadata_is_internally_consistent(self) -> None:
        self.assertEqual(self.fixture["exit_code"], 0)
        self.assertTrue(self.fixture["output_truncated"])
        # The recorded (pre-fix) stdout_bytes sits just *under* the capture
        # limit -- itself evidence of the root-cause bug: byte_count freezes
        # near the cap once truncation begins rather than tracking the true
        # (almost certainly larger) uncapped total.
        self.assertLessEqual(self.fixture["stdout_bytes"], self.fixture["capture_limit_bytes"])
        self.assertGreaterEqual(self.fixture["stdout_bytes"], self.fixture["retained_stdout_bytes"])
        self.assertTrue(self.fixture["cleanup_complete"])
        self.assertEqual(self.fixture["remaining_process_ids"], [])
        self.assertFalse(self.fixture["terminal_event_found_in_retained_prefix"])


# ---------------------------------------------------------------------------
# Layer 3: admissible.agent_backend -- end-to-end via CursorCliAgentBackend
# ---------------------------------------------------------------------------


class TestBackendLevelLargeStreamCapture(unittest.TestCase):
    def setUp(self) -> None:
        from admissible.agent_backend import CursorCliConfig

        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.agent_ws = root / "agent"
        self.target_ws = root / "target"
        self.agent_ws.mkdir()
        self.target_ws.mkdir()
        fake_exe = root / "cursor-agent.cmd"
        fake_exe.write_text("", encoding="utf-8")
        self.config = CursorCliConfig.cursor_agent_preset(command=str(fake_exe))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _request(self):
        from admissible.agent_backend import AgentInvocationRequest

        return AgentInvocationRequest(
            instruction_text="Scaffold the bounded write operations.",
            target_workspace_path=str(self.target_ws),
            agent_workspace_path=str(self.agent_ws),
            timeout_seconds=1.0,
        )

    @staticmethod
    def _fake_managed_oneshot_for(lines: list[str]):
        joined = "\n".join(lines)
        true_total = len(joined.encode("utf-8"))
        truncated_prefix = joined.encode("utf-8")[:DEFAULT_MAX_CAPTURE_BYTES].decode(
            "utf-8", errors="ignore"
        )
        is_truncated = true_total > DEFAULT_MAX_CAPTURE_BYTES

        def fake(
            argv,
            *,
            cwd,
            env,
            timeout_seconds,
            input_text=None,
            max_capture_bytes=0,
            on_stdout_line=None,
        ):
            if on_stdout_line is not None:
                for line in lines:
                    on_stdout_line(line)
            mpr = ManagedProcessResult(
                process_id=555555,
                observed_descendant_ids=[],
                exit_code=0,
                termination_reason="completed",
                cleanup_complete=True,
                remaining_process_ids=[],
                platform_strategy="windows_job_object",
                stdout_bytes=true_total,
                output_truncated=is_truncated,
            )
            return ManagedOneshotResult(
                returncode=0,
                stdout=truncated_prefix,
                stderr="",
                timed_out=False,
                process_result=mpr,
            )

        return fake

    def test_large_stream_still_yields_a_usable_success_response(self) -> None:
        from admissible.agent_backend import AGENT_INVOKE_SUCCESS, CursorCliAgentBackend

        lines = _large_ndjson_lines()
        backend = CursorCliAgentBackend(
            config=self.config, managed_oneshot=self._fake_managed_oneshot_for(lines)
        )
        result = backend.invoke(self._request())

        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertIsNotNone(result.response_text)
        blocks = extract_structured_operation_blocks(result.response_text)
        operations = [op for block in blocks for op in block["operations"]]
        self.assertEqual(len(operations), 4)
        self.assertTrue(result.managed_process_result["output_truncated"])
        self.assertTrue(result.stream_json_diagnostics["raw_output_truncated"])
        self.assertEqual(result.stream_json_diagnostics["terminal_event_count"], 1)
        self.assertGreater(
            result.stream_json_diagnostics["total_stdout_byte_count"], DEFAULT_MAX_CAPTURE_BYTES
        )

    def test_missing_terminal_event_after_large_truncated_output_is_transport_output_truncated(
        self,
    ) -> None:
        from admissible.agent_backend import (
            AGENT_INVOKE_TRANSPORT_OUTPUT_TRUNCATED,
            CursorCliAgentBackend,
        )

        lines = _filler_lines_at_least(600 * 1024)  # no terminal event at all
        backend = CursorCliAgentBackend(
            config=self.config, managed_oneshot=self._fake_managed_oneshot_for(lines)
        )
        result = backend.invoke(self._request())

        self.assertEqual(result.status, AGENT_INVOKE_TRANSPORT_OUTPUT_TRUNCATED)
        self.assertNotEqual(result.status, "malformed")
        self.assertIn("capture-limit", (result.error_message or ""))

    def test_terminal_block_status_includes_the_new_classification(self) -> None:
        from admissible.agent_backend import (
            AGENT_INVOKE_TERMINAL_STATUSES,
            AGENT_INVOKE_TRANSPORT_OUTPUT_TRUNCATED,
        )

        self.assertIn(AGENT_INVOKE_TRANSPORT_OUTPUT_TRUNCATED, AGENT_INVOKE_TERMINAL_STATUSES)


class TestExactlyOnceConsumptionAfterLargeOutput(unittest.TestCase):
    def test_large_response_is_consumed_exactly_once_via_callable_transport(self) -> None:
        from admissible.agent_backend import CallableBackendTransport, CursorCliAgentBackend, CursorCliConfig
        from admissible.agent_transport import TRANSPORT_STATUS_RESPONSE_DETECTED, TRANSPORT_STATUS_WAITING

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agent_ws = tmp_path / "agent"
            target_ws = tmp_path / "target"
            agent_ws.mkdir()
            target_ws.mkdir()
            fake_exe = tmp_path / "cursor-agent.cmd"
            fake_exe.write_text("", encoding="utf-8")
            config = CursorCliConfig.cursor_agent_preset(command=str(fake_exe))

            lines = _large_ndjson_lines()
            backend = CursorCliAgentBackend(
                config=config,
                managed_oneshot=TestBackendLevelLargeStreamCapture._fake_managed_oneshot_for(lines),
            )
            transport = CallableBackendTransport(
                backend, target_workspace_path=str(target_ws), agent_workspace_path=str(agent_ws)
            )
            transport.write_instruction(
                "Scaffold the bounded write operations.",
                turn_number=1,
                session_id="s1",
                instruction_id="i1",
            )

            first = transport.read_response_if_changed()
            self.assertTrue(first.changed)
            self.assertEqual(first.status, TRANSPORT_STATUS_RESPONSE_DETECTED)
            blocks = extract_structured_operation_blocks(first.text)
            operations = [op for block in blocks for op in block["operations"]]
            self.assertEqual(len(operations), 4)

            second = transport.read_response_if_changed()
            self.assertFalse(second.changed)
            self.assertIsNone(second.text)
            self.assertEqual(second.status, TRANSPORT_STATUS_WAITING)


if __name__ == "__main__":
    unittest.main()
