"""RUN_049 PART G -- offline, deterministic replay of REAL captured ACP transcripts.

Loads the sanitized real transcripts this slice's three budgeted real Cursor
ACP calls produced (``benchmark/reports/run049_evidence/*.json``) and replays
their exact recorded server messages back through the unmodified production
``CursorAcpBackend`` client code via a scripted ``ReplayAcpProcess`` -- no real
subprocess, no model call, fully offline and deterministic. Confirms:

- progress events (thought chunks, tool-call events) never become response text;
- message chunks concatenate into exactly the real recorded response;
- a duplicate terminal event (injected into the real transcript) does not
  duplicate ingestion;
- the real policy-violation transcripts (tool-call events in nominal plan
  mode) deterministically reproduce the same rejection when replayed.

This is a *replay* of already-captured real evidence, not a new real call --
it consumes none of the slice's three-call budget.
"""

from __future__ import annotations

import json
import unittest
from collections import deque
from pathlib import Path
from typing import Any

from admissible.agent_backend import AGENT_INVOKE_FAILED, AGENT_INVOKE_SUCCESS, AgentInvocationRequest
from admissible.cursor_acp_transport import (
    STATE_COMPLETED,
    STATE_POLICY_VIOLATION,
    AcpTimeouts,
    CursorAcpBackend,
)
from admissible.managed_process import PLATFORM_STRATEGY_FAKE, ManagedProcessResult, READ_TIMEOUT

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "reports" / "run049_evidence"


def _load_transcript(name: str) -> list[dict[str, Any]]:
    data = json.loads((EVIDENCE_DIR / name).read_text(encoding="utf-8"))
    return data["calls"][0]["transcript"]


class ReplayAcpProcess:
    """Replays a captured real transcript's messages through the unmodified
    ``AcpConnection`` client, rewriting each recorded response/notification's
    correlated request id to whatever id the *live* replayed client code
    actually generated (uuid-based ids are regenerated per run and cannot
    match the originally recorded ones verbatim).

    Walks a single chronological pointer through the interleaved
    client_to_server/server_to_client transcript -- exactly the order the
    real server produced them.
    """

    def __init__(self, transcript: list[dict[str, Any]], *, extra_server_messages: list[dict[str, Any]] | None = None) -> None:
        self._transcript = list(transcript)
        if extra_server_messages:
            # Injected purely for the duplicate-terminal-event test -- appended
            # after the real recorded sequence ends.
            for msg in extra_server_messages:
                self._transcript.append({"direction": "server_to_client", "message": msg})
        self._pos = 0
        self._id_map: dict[Any, Any] = {}
        self._recorded_client_ids_in_order = [
            m["message"]["id"]
            for m in transcript
            if m["direction"] == "client_to_server" and "id" in m["message"]
        ]
        self._live_sent_count = 0
        self.pid = 999999999
        self._exited = False

    # -- managed-process consumer contract ---------------------------------
    def start(self) -> None:
        pass

    def send_stdin(self, text: str) -> None:
        for line in text.splitlines():
            if not line.strip():
                continue
            msg = json.loads(line)
            if "id" in msg and "method" in msg:
                if self._live_sent_count < len(self._recorded_client_ids_in_order):
                    recorded_id = self._recorded_client_ids_in_order[self._live_sent_count]
                    self._id_map[recorded_id] = msg["id"]
                self._live_sent_count += 1
            # advance past this client_to_server transcript entry, if present
            while self._pos < len(self._transcript) and self._transcript[self._pos]["direction"] == "client_to_server":
                self._pos += 1

    def close_stdin(self) -> None:
        pass

    def read_stdout_line(self, timeout: float | None) -> str | None:
        while self._pos < len(self._transcript) and self._transcript[self._pos]["direction"] == "client_to_server":
            self._pos += 1
        if self._pos >= len(self._transcript):
            self._exited = True
            return None
        entry = self._transcript[self._pos]
        self._pos += 1
        message = dict(entry["message"])
        if "id" in message and message["id"] in self._id_map:
            message = dict(message)
            message["id"] = self._id_map[message["id"]]
        return json.dumps(message) + "\n"

    def poll(self) -> int | None:
        return 0 if self._exited else None

    def wait(self, timeout: float | None = None) -> int | None:
        return 0 if self._exited else None

    def terminate(self, *, reason: str = "cancelled") -> ManagedProcessResult:
        self._exited = True
        return ManagedProcessResult(
            process_id=self.pid,
            exit_code=0,
            termination_reason=reason,
            cleanup_complete=True,
            remaining_process_ids=[],
            platform_strategy=PLATFORM_STRATEGY_FAKE,
        )

    def finish(self, *, reason: str = "completed") -> None:
        self._exited = True

    def result(self) -> ManagedProcessResult:
        return ManagedProcessResult(process_id=self.pid, platform_strategy=PLATFORM_STRATEGY_FAKE)

    def captured_stderr(self) -> str:
        return ""


def _replay_factory(transcript: list[dict[str, Any]], **kwargs: Any):
    def factory(argv, cwd, env):
        return ReplayAcpProcess(transcript, **kwargs)

    return factory


def _fast_timeouts() -> AcpTimeouts:
    return AcpTimeouts(
        server_start_seconds=2.0, handshake_seconds=2.0, request_acceptance_seconds=2.0,
        idle_no_progress_seconds=1.0, absolute_request_seconds=3.0,
        cancellation_seconds=0.5, cleanup_seconds=0.5,
    )


def _request() -> AgentInvocationRequest:
    return AgentInvocationRequest(
        instruction_text="Return exactly: ADMISSIBLE_ACP_PLAN_MODE_PROBE_OK",
        session_id="replay_test", turn_number=1, instruction_id="replay-instr-1",
        target_workspace_path="unused_target", agent_workspace_path="unused_agent",
    )


class RealTranscriptReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Call 3 (the real repair rehearsal) drove CursorAcpBackend directly
        # via admissible.diagnostics.acp_repair_rehearsal without the
        # TranscriptRecordingProcess wrapper calls 1/2 used, so no raw
        # JSON-RPC transcript was captured for it -- only its invocation
        # telemetry (acp_invocation_state, tool_event_count, workspace
        # mutation diff, managed_process_result), which the promotion-gate
        # report consumes directly from run049_call3_repair_rehearsal.json.
        cls.call1_transcript = _load_transcript("run049_call1_plan_mode_tiny.json")
        cls.call2_transcript = _load_transcript("run049_call2_plan_mode_structured_proposal.json")

    def test_call1_replay_reproduces_the_exact_recorded_response(self) -> None:
        backend = CursorAcpBackend(
            process_factory=_replay_factory(self.call1_transcript), timeouts=_fast_timeouts()
        )
        result = backend.invoke(_request())
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertEqual(result.response_text, "ADMISSIBLE_ACP_PLAN_MODE_PROBE_OK")
        self.assertEqual(result.acp_invocation_state, STATE_COMPLETED)
        self.assertTrue(result.acp_telemetry["plan_mode_enforced"])
        self.assertEqual(result.acp_telemetry["effective_mode_before_prompt"], "plan")

    def test_call1_thought_chunks_never_contribute_to_response_text(self) -> None:
        backend = CursorAcpBackend(
            process_factory=_replay_factory(self.call1_transcript), timeouts=_fast_timeouts()
        )
        result = backend.invoke(_request())
        thought_texts = [
            (m["message"].get("params") or {}).get("update", {}).get("content", {}).get("text")
            for m in self.call1_transcript
            if m["direction"] == "server_to_client"
            and (m["message"].get("params") or {}).get("update", {}).get("sessionUpdate") == "agent_thought_chunk"
        ]
        # this real transcript's tiny probe had no thought chunks; assert the
        # invariant generically: no thought-chunk text ever appears verbatim
        # inside the ingested response unless it also matches a message chunk.
        message_texts = "".join(
            (m["message"].get("params") or {}).get("update", {}).get("content", {}).get("text") or ""
            for m in self.call1_transcript
            if m["direction"] == "server_to_client"
            and (m["message"].get("params") or {}).get("update", {}).get("sessionUpdate") == "agent_message_chunk"
        )
        self.assertEqual(result.response_text, message_texts.strip())
        for text in thought_texts:
            if text:
                self.assertNotIn(text, result.response_text or "")

    def test_call1_duplicate_terminal_event_does_not_duplicate_ingest(self) -> None:
        # Inject a second copy of the real terminal result after the genuine
        # one -- exactly-once must ignore it (RUN_047/048 invariant, now
        # proven against real captured data too).
        terminal = next(
            m["message"] for m in reversed(self.call1_transcript)
            if m["direction"] == "server_to_client" and "result" in m["message"]
        )
        backend = CursorAcpBackend(
            process_factory=_replay_factory(self.call1_transcript, extra_server_messages=[dict(terminal)]),
            timeouts=_fast_timeouts(),
        )
        result = backend.invoke(_request())
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertEqual(result.response_text, "ADMISSIBLE_ACP_PLAN_MODE_PROBE_OK")
        self.assertEqual(result.acp_telemetry["counters"]["usable_responses"], 1)

    def test_call2_structured_proposal_policy_violation_replays_deterministically(self) -> None:
        backend = CursorAcpBackend(
            process_factory=_replay_factory(self.call2_transcript), timeouts=_fast_timeouts()
        )
        result = backend.invoke(_request())
        self.assertEqual(result.status, AGENT_INVOKE_FAILED)
        self.assertEqual(result.acp_invocation_state, STATE_POLICY_VIOLATION)
        self.assertIsNone(result.response_text)
        self.assertTrue(result.acp_telemetry["policy_violation_reason"].startswith("tool_call_event"))


if __name__ == "__main__":
    unittest.main()
