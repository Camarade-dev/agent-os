"""Deterministic in-memory fake Cursor ACP server (slice ADMISSIBLE_RUN_047, PART J).

``FakeAcpProcess`` implements the managed-process *consumer* contract that
``admissible.cursor_acp_transport.AcpConnection`` drives (``start`` /
``send_stdin`` / ``read_stdout_line`` / ``poll`` / ``terminate`` / ``finish`` /
``result`` / ``captured_stderr``), backed by two in-memory queues and a scripted
server thread. It speaks the same newline-delimited JSON-RPC 2.0 framing the
real ``cursor-agent acp`` server uses, so the whole ACP client is exercised with
zero real subprocesses and zero model calls.

Every scenario the RUN_047 spec (PART J.39) asks for is covered.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Any

from admissible.managed_process import (
    PLATFORM_STRATEGY_FAKE,
    TERMINATION_CLEANUP_FAILED,
    TERMINATION_COMPLETED,
    READ_TIMEOUT,
    ManagedProcessResult,
)

# -- scenarios ---------------------------------------------------------------
SCENARIO_HANDSHAKE_SUCCESS = "handshake_success"
SCENARIO_HANDSHAKE_REJECT = "handshake_reject"
SCENARIO_UNSUPPORTED_PROTOCOL = "unsupported_protocol"
SCENARIO_SUCCESS = "success"
SCENARIO_PROVIDER_ERROR = "provider_error"
SCENARIO_MALFORMED_THEN_SUCCESS = "malformed_then_success"
SCENARIO_DUPLICATE_TERMINAL = "duplicate_terminal"
SCENARIO_DISCONNECT_BEFORE_ACCEPTANCE = "disconnect_before_acceptance"
SCENARIO_DISCONNECT_AFTER_ACCEPTANCE = "disconnect_after_acceptance"
SCENARIO_IDLE_TIMEOUT = "idle_timeout"
SCENARIO_TOTAL_TIMEOUT_PROGRESS = "total_timeout_progress"
SCENARIO_CANCEL_ACK = "cancel_ack"
SCENARIO_CANCEL_IGNORED = "cancel_ignored"

_STDIN_CLOSED = object()
_EOF = None  # output-queue EOF sentinel


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class FakeAcpProcess:
    """A scripted, in-memory ACP server exposing the managed-process contract."""

    def __init__(
        self,
        scenario: str,
        *,
        protocol_version: int = 1,
        progress_count: int = 2,
        response_text: str = "Task acknowledged by the fake ACP agent.",
        leak_on_terminate: bool = False,
        force_needed: bool = False,
        drip_interval: float = 0.02,
        pid: int = 424242,
        session_mode: str = "agent",
        set_mode_supported: bool = True,
        set_mode_emits_confirmation: bool = True,
        set_mode_confirmed_mode: str | None = None,
        mid_turn_mode_change: str | None = None,
        emit_tool_call: bool = False,
    ) -> None:
        self.scenario = scenario
        self.protocol_version = protocol_version
        self.progress_count = max(1, progress_count)
        self.response_text = response_text
        self.session_mode = session_mode
        self.set_mode_supported = set_mode_supported
        # RUN_049 PART D: RUN_048 confirmed the real server emits a
        # `current_mode_update` notification alongside the bare `session/set_mode`
        # RPC ack. `set_mode_emits_confirmation=False` models a server that acks
        # but never sends that notification; `set_mode_confirmed_mode` models a
        # server that acks "plan" but the *effective* mode it reports back is
        # something else -- both must make CursorAcpBackend fail closed.
        self.set_mode_emits_confirmation = set_mode_emits_confirmation
        self.set_mode_confirmed_mode = set_mode_confirmed_mode
        # A mode change away from plan (or a tool-call event), emitted mid-turn
        # (after the prompt is accepted) -- both must be rejected as proposal-
        # only policy violations (PART D.23/24).
        self.mid_turn_mode_change = mid_turn_mode_change
        self.emit_tool_call = emit_tool_call
        self.set_mode_requested = None
        self._leak = leak_on_terminate
        self._force_needed = force_needed
        self._drip_interval = drip_interval
        self.pid = pid

        self._in: "Queue[Any]" = Queue()
        self._out: "Queue[Any]" = Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._eof_returned = False
        self._exited = False
        self._started_at: str | None = None
        self._result: ManagedProcessResult | None = None
        self._session_id = "sess-fake-0001"

        # observable test hooks
        self.sent_messages: list[dict[str, Any]] = []
        self.cancel_received = False
        self.terminate_called = False
        self.finish_called = False
        self.graceful_attempted = False
        self.force_attempted = False

    # -- managed-process consumer contract ---------------------------------

    def start(self) -> None:
        self._started_at = _now_iso()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def send_stdin(self, text: str) -> None:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                msg = {"_unparsed": line}
            self.sent_messages.append(msg)
            if msg.get("method") == "session/cancel":
                self.cancel_received = True  # record synchronously for tests
            self._in.put(line)

    def close_stdin(self) -> None:
        self._in.put(_STDIN_CLOSED)

    def read_stdout_line(self, timeout: float | None) -> str | None:
        if self._eof_returned:
            return _EOF
        try:
            item = self._out.get(timeout=timeout if timeout is not None else 0.0)
        except Empty:
            return READ_TIMEOUT
        if item is _EOF:
            self._eof_returned = True
            return _EOF
        return item

    def poll(self) -> int | None:
        return 0 if self._exited else None

    def wait(self, timeout: float | None = None) -> int | None:
        return 0 if self._exited else None

    def terminate(self, *, reason: str = "cancelled") -> ManagedProcessResult:
        self.terminate_called = True
        self.graceful_attempted = True
        if self._force_needed or self._leak:
            self.force_attempted = True
        self._stop.set()
        self._exited = True
        remaining = [self.pid + 10] if self._leak else []
        self._result = ManagedProcessResult(
            process_id=self.pid,
            observed_descendant_ids=[self.pid + 1, self.pid + 2],
            started_at=self._started_at,
            exited_at=_now_iso(),
            exit_code=None if self._leak else 1,
            termination_reason=(TERMINATION_CLEANUP_FAILED if self._leak else reason),
            graceful_termination_attempted=True,
            force_termination_attempted=self.force_attempted,
            cleanup_complete=not self._leak,
            remaining_process_ids=remaining,
            platform_strategy=PLATFORM_STRATEGY_FAKE,
        )
        self._join()
        return self._result

    def finish(self, *, reason: str = TERMINATION_COMPLETED) -> None:
        self.finish_called = True
        self._stop.set()
        self._exited = True
        self._result = ManagedProcessResult(
            process_id=self.pid,
            observed_descendant_ids=[self.pid + 1, self.pid + 2],
            started_at=self._started_at,
            exited_at=_now_iso(),
            exit_code=0,
            termination_reason=reason,
            cleanup_complete=True,
            remaining_process_ids=[],
            platform_strategy=PLATFORM_STRATEGY_FAKE,
        )
        self._join()

    def result(self) -> ManagedProcessResult:
        if self._result is None:
            self._result = ManagedProcessResult(
                process_id=self.pid,
                started_at=self._started_at,
                platform_strategy=PLATFORM_STRATEGY_FAKE,
            )
        return self._result

    def captured_stderr(self) -> str:
        return ""

    def _join(self) -> None:
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    # -- scripted server ---------------------------------------------------

    def _emit(self, message: dict[str, Any]) -> None:
        self._out.put(json.dumps(message, ensure_ascii=False) + "\n")

    def _emit_raw(self, raw: str) -> None:
        self._out.put(raw if raw.endswith("\n") else raw + "\n")

    def _emit_eof(self) -> None:
        self._exited = True
        self._out.put(_EOF)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw = self._in.get(timeout=0.05)
            except Empty:
                continue
            if raw is _STDIN_CLOSED:
                self._emit_eof()
                return
            try:
                msg = json.loads(raw.strip())
            except ValueError:
                continue
            method = msg.get("method")
            msg_id = msg.get("id")
            if method == "initialize":
                if not self._handle_initialize(msg_id):
                    return
            elif method == "session/new":
                if not self._handle_session_new(msg_id):
                    return
            elif method == "session/set_mode":
                self._handle_set_mode(msg_id, msg.get("params") or {})
            elif method == "session/prompt":
                if not self._handle_prompt(msg_id, msg.get("params") or {}):
                    return
            elif method == "session/cancel":
                self.cancel_received = True
                if self.scenario == SCENARIO_CANCEL_ACK:
                    self._emit_eof()
                    return
                # SCENARIO_CANCEL_IGNORED: deliberately do nothing.

    def _handle_initialize(self, msg_id: Any) -> bool:
        if self.scenario == SCENARIO_HANDSHAKE_REJECT:
            self._emit(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": "handshake rejected by fake server"},
                }
            )
            return True
        version = 999 if self.scenario == SCENARIO_UNSUPPORTED_PROTOCOL else self.protocol_version
        self._emit(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": version,
                    "agentCapabilities": {
                        "loadSession": True,
                        "promptCapabilities": {"image": True, "audio": False},
                    },
                    "authMethods": ["cursor_login"],
                },
            }
        )
        return True

    def _handle_session_new(self, msg_id: Any) -> bool:
        if self.scenario == SCENARIO_DISCONNECT_BEFORE_ACCEPTANCE:
            self._emit_eof()
            return False
        self._emit(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "sessionId": self._session_id,
                    "modes": {
                        "currentModeId": self.session_mode,
                        "availableModes": [
                            {"id": "agent", "name": "Agent"},
                            {"id": "plan", "name": "Plan"},
                            {"id": "ask", "name": "Ask"},
                        ],
                    },
                },
            }
        )
        return True

    def _handle_set_mode(self, msg_id: Any, params: dict[str, Any]) -> None:
        self.set_mode_requested = params.get("modeId")
        if self.set_mode_supported:
            requested = params.get("modeId") or self.session_mode
            confirmed = self.set_mode_confirmed_mode if self.set_mode_confirmed_mode is not None else requested
            self.session_mode = confirmed
            self._emit({"jsonrpc": "2.0", "id": msg_id, "result": {}})
            if self.set_mode_emits_confirmation:
                self._emit_current_mode_update(confirmed)
        else:
            self._emit(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": "session/set_mode not supported"},
                }
            )

    def _emit_current_mode_update(self, mode: str) -> None:
        self._emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": self._session_id,
                    "update": {"sessionUpdate": "current_mode_update", "currentModeId": mode},
                },
            }
        )

    def _emit_tool_call_event(self) -> None:
        self._emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": self._session_id,
                    "update": {"sessionUpdate": "tool_call", "toolName": "write_file"},
                },
            }
        )

    def _handle_prompt(self, req_id: Any, params: dict[str, Any]) -> bool:
        scenario = self.scenario
        if scenario == SCENARIO_PROVIDER_ERROR:
            self._emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32001, "message": "provider refused the prompt"},
                }
            )
            return True
        if scenario == SCENARIO_IDLE_TIMEOUT:
            # Emit nothing: the client's idle/no-progress timeout must fire.
            return True
        if scenario == SCENARIO_DISCONNECT_AFTER_ACCEPTANCE:
            self._emit_update("agent_message_chunk", "partial ")
            self._emit_eof()
            return False
        if scenario == SCENARIO_TOTAL_TIMEOUT_PROGRESS:
            # Drip progress forever: idle liveness stays fresh, so only the
            # absolute request timeout can end this.
            while not self._stop.is_set():
                self._emit_update("agent_thought_chunk", None)
                time.sleep(self._drip_interval)
            return True
        if scenario in (SCENARIO_CANCEL_ACK, SCENARIO_CANCEL_IGNORED):
            # Accept the prompt with one progress event, then hang awaiting a
            # cancel (or a timeout-driven tree termination).
            self._emit_update("agent_message_chunk", "working ")
            return True

        # Happy-path family: N progress events, then a terminal result.
        if scenario == SCENARIO_MALFORMED_THEN_SUCCESS:
            self._emit_raw("{ this is not valid json ]")
        if self.mid_turn_mode_change is not None:
            self._emit_current_mode_update(self.mid_turn_mode_change)
        if self.emit_tool_call:
            self._emit_tool_call_event()
        self._emit_message_chunks(req_id)
        self._emit_terminal_success(req_id)
        if scenario == SCENARIO_DUPLICATE_TERMINAL:
            # Replay the terminal result: exactly-once must ignore the duplicate.
            self._emit_terminal_success(req_id)
        return True

    def _emit_message_chunks(self, req_id: Any) -> None:
        text = self.response_text
        count = min(self.progress_count, max(1, len(text)))
        size = max(1, (len(text) + count - 1) // count)
        for i in range(0, len(text), size):
            self._emit_update("agent_message_chunk", text[i : i + size])

    def _emit_terminal_success(self, req_id: Any) -> None:
        self._emit({"jsonrpc": "2.0", "id": req_id, "result": {"stopReason": "end_turn"}})

    def _emit_update(self, session_update: str, text: str | None) -> None:
        update: dict[str, Any] = {"sessionUpdate": session_update}
        if text is not None:
            update["content"] = {"type": "text", "text": text}
        self._emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {"sessionId": self._session_id, "update": update},
            }
        )


def fake_process_factory(scenario: str, **kwargs: Any):
    """Return a ``process_factory`` for ``CursorAcpBackend`` that yields a scripted
    ``FakeAcpProcess`` and records the created instance for assertions."""
    created: list[FakeAcpProcess] = []

    def factory(argv: list[str], cwd: str, env: dict[str, str] | None) -> FakeAcpProcess:
        proc = FakeAcpProcess(scenario, **kwargs)
        created.append(proc)
        return proc

    factory.created = created  # type: ignore[attr-defined]
    return factory


__all__ = [
    "FakeAcpProcess",
    "fake_process_factory",
    "SCENARIO_HANDSHAKE_SUCCESS",
    "SCENARIO_HANDSHAKE_REJECT",
    "SCENARIO_UNSUPPORTED_PROTOCOL",
    "SCENARIO_SUCCESS",
    "SCENARIO_PROVIDER_ERROR",
    "SCENARIO_MALFORMED_THEN_SUCCESS",
    "SCENARIO_DUPLICATE_TERMINAL",
    "SCENARIO_DISCONNECT_BEFORE_ACCEPTANCE",
    "SCENARIO_DISCONNECT_AFTER_ACCEPTANCE",
    "SCENARIO_IDLE_TIMEOUT",
    "SCENARIO_TOTAL_TIMEOUT_PROGRESS",
    "SCENARIO_CANCEL_ACK",
    "SCENARIO_CANCEL_IGNORED",
]
