"""Cursor ACP-backed callable backend (slice ADMISSIBLE_RUN_047).

An experimental, structured transport that drives Cursor Agent's real (hidden
but confirmed-live in RUN_046) ``cursor-agent acp`` server over newline-delimited
JSON-RPC 2.0 on stdio, instead of the opaque one-shot ``--print`` stdout.

Why: the one-shot transport is fully buffered (no progress signal), pays a
13-16s cold start per turn, and can only be cancelled by killing the process
tree. ACP gives request IDs, ``session/update`` progress events, a targeted
``session/cancel``, and structured terminal ``result``/``error`` — everything a
bounded, cancellable, observable transport needs.

**Protocol provenance.** Only the ``initialize`` handshake (protocolVersion,
agentCapabilities, authMethods) was exercised *live* in RUN_046. The
``session/new`` / ``session/prompt`` / ``session/update`` / ``session/cancel``
shapes below follow the Agent Client Protocol as named in the installed CLI's
own bundled source, but their exact field layouts are **spec-derived, not yet
confirmed live** — see ``docs/admissible-cursor-acp-transport.md``. Parsing is
therefore deliberately tolerant, and every unknown is documented rather than
invented (PART B.7).

Hard constraints honored (RUN_047):

- fixed executable chain (``cursor-agent acp``); no session/model/UI input ever
  supplies the executable, ACP command, flags, or a working directory outside
  the isolated agent workspace (PART C.12);
- the ACP server process is owned by the RUN_047 managed-process lifecycle
  (PART C.13, A);
- per-invocation server lifecycle — the narrowest reliable choice for this spike
  (PART C.14; trade-off documented in the module docstring section below and the
  companion doc);
- no automatic fallback after an uncertain timeout/disconnect (PART H.33, E.21);
- transport failures never consume the semantic repair budget (PART E.23);
- no model provider is contacted in the default unit suite — a deterministic
  fake ACP server drives every unit test (PART J).

Server lifecycle trade-off (PART C.14): Admissible reconstructs a fresh
controller/transport per HTTP tick, so a long-lived (process/control-surface/
session-scoped) ACP server would need new cross-tick persistence to survive
reconstruction — out of scope for a spike and a new failure surface. A
*per-invocation* server (spawn -> handshake -> one prompt -> shutdown) is the
narrowest lifecycle that fits the existing tick machine unchanged; it re-pays the
~1.1s handshake per turn (still far cheaper than the 13-16s one-shot cold start),
in exchange for zero new persistence and a trivially-clean shutdown every turn.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from admissible.agent_backend import (
    AGENT_AVAILABILITY_AVAILABLE,
    AGENT_AVAILABILITY_NOT_CONFIGURED,
    AGENT_AVAILABILITY_UNAVAILABLE,
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    AGENT_INVOKE_EMPTY_SUCCESS,
    AGENT_INVOKE_FAILED,
    AGENT_INVOKE_SUCCESS,
    AGENT_INVOKE_TIMEOUT,
    AgentBackend,
    AgentBackendAvailability,
    AgentInvocationRequest,
    AgentInvocationResult,
    CursorCliConfig,
    build_cursor_agent_safe_environment,
    is_cursor_agent_command,
)
from admissible.managed_process import (
    READ_TIMEOUT,
    TERMINATION_CANCELLED,
    TERMINATION_COMPLETED,
    TERMINATION_HARD_TIMEOUT,
    ManagedProcess,
    ManagedProcessResult,
)
from admissible.transport_health import (
    OUTCOME_ACCEPTED,
    OUTCOME_CANCELLED,
    OUTCOME_CLEANUP_FAILURE,
    OUTCOME_EMPTY_RESPONSE,
    OUTCOME_HANDSHAKE_OK,
    OUTCOME_IDLE_TIMEOUT,
    OUTCOME_PROTOCOL_ERROR,
    OUTCOME_PROVIDER_ERROR,
    OUTCOME_TOTAL_TIMEOUT,
    OUTCOME_UNCERTAIN_COMPLETION,
    OUTCOME_USABLE_COMPLETION,
    TransportHealth,
)

# -- backend / transport identity (PART C.11, H.34) --------------------------
BACKEND_ID_CURSOR_ACP = "cursor_acp"
BACKEND_ID_CURSOR_ONESHOT = "cursor_cli_oneshot"
TRANSPORT_LABEL_ACP = "Cursor Agent ACP"
TRANSPORT_LABEL_ONESHOT = "Cursor Agent one-shot"

# -- transport selection (PART H.31) -----------------------------------------
CURSOR_TRANSPORT_ENV = "ADMISSIBLE_CURSOR_TRANSPORT"
TRANSPORT_ACP = "acp"
TRANSPORT_ONESHOT = "oneshot"
DEFAULT_TRANSPORT = TRANSPORT_ONESHOT  # compatibility default until the gate is met

# -- structured invocation states (PART D.15) --------------------------------
STATE_CREATED = "created"
STATE_SERVER_STARTING = "server_starting"
STATE_HANDSHAKE_PENDING = "handshake_pending"
STATE_READY = "ready"
STATE_REQUEST_SUBMITTED = "request_submitted"
STATE_ACCEPTED = "accepted"
STATE_RUNNING = "running"
STATE_PROGRESS = "progress"
STATE_RESPONSE_READY = "response_ready"
STATE_COMPLETED = "completed"
STATE_PROVIDER_ERROR = "provider_error"
STATE_PROTOCOL_ERROR = "protocol_error"
STATE_DISCONNECTED = "disconnected"
STATE_CANCELLATION_REQUESTED = "cancellation_requested"
STATE_CANCELLED = "cancelled"
STATE_TIMED_OUT_IDLE = "timed_out_idle"
STATE_TIMED_OUT_TOTAL = "timed_out_total"
STATE_UNCERTAIN_COMPLETION = "uncertain_completion"
STATE_CLEANUP_FAILED = "cleanup_failed"

ACP_INVOCATION_STATES = frozenset(
    {
        STATE_CREATED,
        STATE_SERVER_STARTING,
        STATE_HANDSHAKE_PENDING,
        STATE_READY,
        STATE_REQUEST_SUBMITTED,
        STATE_ACCEPTED,
        STATE_RUNNING,
        STATE_PROGRESS,
        STATE_RESPONSE_READY,
        STATE_COMPLETED,
        STATE_PROVIDER_ERROR,
        STATE_PROTOCOL_ERROR,
        STATE_DISCONNECTED,
        STATE_CANCELLATION_REQUESTED,
        STATE_CANCELLED,
        STATE_TIMED_OUT_IDLE,
        STATE_TIMED_OUT_TOTAL,
        STATE_UNCERTAIN_COMPLETION,
        STATE_CLEANUP_FAILED,
    }
)

# States reached before the prompt is ever submitted: a disconnect/timeout here
# is *provable* non-acceptance, the only condition that permits one bounded
# automatic retry (PART E.22).
_PRE_SUBMIT_STATES = frozenset(
    {STATE_CREATED, STATE_SERVER_STARTING, STATE_HANDSHAKE_PENDING, STATE_READY}
)

# -- ACP methods (named in the installed CLI's bundled source) ----------------
ACP_METHOD_INITIALIZE = "initialize"
ACP_METHOD_SESSION_NEW = "session/new"
ACP_METHOD_SESSION_PROMPT = "session/prompt"
ACP_METHOD_SESSION_CANCEL = "session/cancel"
ACP_METHOD_SESSION_UPDATE = "session/update"
# session/set_mode confirmed live in RUN_048: session/new returns a `modes` block
# whose default `currentModeId` is "agent" (full tool/write access). Admissible
# requires proposal-only, so the ACP backend forces read-only plan mode — the
# ACP analogue of the one-shot transport's ``--mode plan``.
ACP_METHOD_SESSION_SET_MODE = "session/set_mode"
ACP_MODE_PLAN = "plan"
ACP_MODE_AGENT = "agent"
ACP_MODE_ASK = "ask"

# Protocol versions this spike is willing to speak (confirmed live: 1).
SUPPORTED_PROTOCOL_VERSIONS = frozenset({1})

_PROGRESS_SUMMARY_MAX_CHARS = 200
_MAX_PROGRESS_EVENTS = 200
_DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bounded(text: str | None, limit: int = _PROGRESS_SUMMARY_MAX_CHARS) -> str | None:
    if not text:
        return None
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


def select_transport(env: dict[str, str] | None = None) -> str:
    """Resolve the configured transport (``acp`` | ``oneshot``); default oneshot.

    An unrecognized value falls back to the compatibility default; it never
    silently upgrades to ACP (PART H).
    """
    raw = (dict(os.environ if env is None else env).get(CURSOR_TRANSPORT_ENV) or "").strip().lower()
    if raw == TRANSPORT_ACP:
        return TRANSPORT_ACP
    if raw == TRANSPORT_ONESHOT:
        return TRANSPORT_ONESHOT
    return DEFAULT_TRANSPORT


# ---------------------------------------------------------------------------
# Multi-dimensional timeouts (PART E.18)
# ---------------------------------------------------------------------------


@dataclass
class AcpTimeouts:
    server_start_seconds: float = 20.0
    handshake_seconds: float = 15.0
    request_acceptance_seconds: float = 30.0
    idle_no_progress_seconds: float = 60.0
    absolute_request_seconds: float = 240.0
    cancellation_seconds: float = 10.0
    cleanup_seconds: float = 10.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_start_seconds": self.server_start_seconds,
            "handshake_seconds": self.handshake_seconds,
            "request_acceptance_seconds": self.request_acceptance_seconds,
            "idle_no_progress_seconds": self.idle_no_progress_seconds,
            "absolute_request_seconds": self.absolute_request_seconds,
            "cancellation_seconds": self.cancellation_seconds,
            "cleanup_seconds": self.cleanup_seconds,
        }


# ---------------------------------------------------------------------------
# Bounded progress + telemetry (PART D.16/17, F.24)
# ---------------------------------------------------------------------------


@dataclass
class AcpProgressEvent:
    """One bounded, human-readable progress event. Never stores raw token
    streams or complete internal reasoning (PART F.24)."""

    sequence: int
    timestamp: str
    event_type: str
    summary: str | None
    request_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "summary": self.summary,
            "request_id": self.request_id,
        }


@dataclass
class AcpInvocationTelemetry:
    """Durable, bounded ACP invocation telemetry (PART D.16/17)."""

    request_id: str | None = None
    session_id: str | None = None
    protocol_version: int | None = None
    session_mode_before: str | None = None
    session_mode_enforced: str | None = None
    plan_mode_enforced: bool = False
    handshake_duration_ms: float | None = None
    accepted_at: str | None = None
    first_progress_at: str | None = None
    last_progress_at: str | None = None
    completed_at: str | None = None
    progress_event_count: int = 0
    terminal_event: str | None = None
    response_bytes: int = 0
    invocation_state: str = STATE_CREATED
    retry_safe: bool = False
    progress_events: list[dict[str, Any]] = field(default_factory=list)
    managed_process_result: dict[str, Any] | None = None

    # separate transport-vs-semantic counters (PART D.17)
    transport_attempt_count: int = 0
    acp_request_count: int = 0
    provider_retries: int = 0
    progress_events_total: int = 0
    usable_responses: int = 0
    model_turns: int = 0
    semantic_repair_rounds: int = 0  # always 0 here: transport never consumes it

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "protocol_version": self.protocol_version,
            "session_mode_before": self.session_mode_before,
            "session_mode_enforced": self.session_mode_enforced,
            "plan_mode_enforced": self.plan_mode_enforced,
            "handshake_duration_ms": self.handshake_duration_ms,
            "accepted_at": self.accepted_at,
            "first_progress_at": self.first_progress_at,
            "last_progress_at": self.last_progress_at,
            "completed_at": self.completed_at,
            "progress_event_count": self.progress_event_count,
            "terminal_event": self.terminal_event,
            "response_bytes": self.response_bytes,
            "invocation_state": self.invocation_state,
            "retry_safe": self.retry_safe,
            "progress_events": list(self.progress_events),
            "managed_process_result": self.managed_process_result,
            "counters": {
                "transport_attempt_count": self.transport_attempt_count,
                "acp_request_count": self.acp_request_count,
                "provider_retries": self.provider_retries,
                "progress_events_total": self.progress_events_total,
                "usable_responses": self.usable_responses,
                "model_turns": self.model_turns,
                "semantic_repair_rounds": self.semantic_repair_rounds,
            },
        }


# ---------------------------------------------------------------------------
# ACP JSON-RPC connection over a managed process (framing: ndjson)
# ---------------------------------------------------------------------------

# Message-classification sentinels returned by AcpConnection.read_message.
MSG_EOF = "eof"
MSG_TIMEOUT = "timeout"
MSG_MALFORMED = "malformed"
MSG_JSON = "json"


class AcpConnection:
    """Newline-delimited JSON-RPC 2.0 over a managed process's stdio.

    The process is any object exposing the managed-process contract
    (``send_stdin``/``read_stdout_line``/``poll``/...), so tests drive a
    deterministic in-memory fake with zero real subprocesses.
    """

    def __init__(self, process: Any) -> None:
        self.process = process
        self._closed_write = False

    def send(self, method: str, params: dict[str, Any], *, request_id: Any = None) -> None:
        """Write one JSON-RPC request or notification line."""
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            message["id"] = request_id
        line = json.dumps(message, ensure_ascii=False) + "\n"
        self.process.send_stdin(line)

    def read_message(self, timeout: float) -> tuple[str, Any]:
        """Read + parse one JSON-RPC line.

        Returns ``(MSG_JSON, dict)``, ``(MSG_EOF, None)``, ``(MSG_TIMEOUT, None)``,
        or ``(MSG_MALFORMED, raw)``. Blank lines are skipped transparently.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            line = self.process.read_stdout_line(remaining)
            if line == READ_TIMEOUT:
                return (MSG_TIMEOUT, None)
            if line is None:
                return (MSG_EOF, None)
            stripped = line.strip()
            if not stripped:
                if time.monotonic() >= deadline:
                    return (MSG_TIMEOUT, None)
                continue
            try:
                return (MSG_JSON, json.loads(stripped))
            except (ValueError, TypeError):
                return (MSG_MALFORMED, _bounded(stripped))

    def close_write(self) -> None:
        if not self._closed_write:
            self._closed_write = True
            try:
                self.process.close_stdin()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# ACP config (fixed executable chain)
# ---------------------------------------------------------------------------


@dataclass
class CursorAcpConfig:
    """Fixed, discovered executable chain for the ACP server. No session/UI
    input supplies the executable, command, flags, or working directory."""

    cli_config: CursorCliConfig
    timeouts: AcpTimeouts = field(default_factory=AcpTimeouts)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "CursorAcpConfig":
        return cls(cli_config=CursorCliConfig.cursor_agent_preset())

    @property
    def command_path(self) -> str | None:
        return self.cli_config.command_path

    def resolved_command(self) -> str | None:
        return self.cli_config.resolved_command()

    def acp_available(self) -> bool:
        return bool(self.resolved_command()) and is_cursor_agent_command(self.command_path)

    def acp_argv(self) -> list[str] | None:
        command = self.resolved_command()
        if not command:
            return None
        return [command, "acp"]  # fixed; never session/UI-supplied

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_path": self.command_path,
            "resolved_command": self.resolved_command(),
            "acp_available": self.acp_available(),
            "acp_argv_shape": ["<cursor-agent>", "acp"],
            "timeouts": self.timeouts.to_dict(),
        }


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

ProcessFactory = Callable[[list[str], str, dict[str, str] | None], Any]


def _default_process_factory(
    argv: list[str], cwd: str, env: dict[str, str] | None
) -> ManagedProcess:
    return ManagedProcess(argv, cwd=cwd, env=env, want_stdin=True)


class CursorAcpBackend(AgentBackend):
    """ACP-backed callable backend satisfying the model-agnostic boundary.

    ``invoke`` runs one complete, bounded, cancellable ACP lifecycle
    (detect -> start -> handshake -> session -> prompt -> progress -> terminal ->
    canonical response -> shutdown/cleanup) and returns a canonical
    ``AgentInvocationResult`` — the same shape the extraction/admission pipeline
    already consumes.
    """

    backend_id = BACKEND_ID_CURSOR_ACP
    label = TRANSPORT_LABEL_ACP

    def __init__(
        self,
        config: CursorAcpConfig | None = None,
        *,
        process_factory: ProcessFactory | None = None,
        health: TransportHealth | None = None,
        timeouts: AcpTimeouts | None = None,
        env_base: dict[str, str] | None = None,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.config = config if config is not None else CursorAcpConfig.from_env()
        if timeouts is not None:
            self.config.timeouts = timeouts
        self._process_factory = process_factory or _default_process_factory
        self.health = health if health is not None else TransportHealth(backend_id=self.backend_id)
        self._env_base = env_base
        self._max_response_bytes = max_response_bytes
        self._last_status: str | None = None
        self._last_telemetry: AcpInvocationTelemetry | None = None

    # -- availability -------------------------------------------------------

    def availability(self) -> AgentBackendAvailability:
        cfg = self.config
        if not cfg.command_path:
            return AgentBackendAvailability(
                status=AGENT_AVAILABILITY_NOT_CONFIGURED,
                configured=False,
                message="Cursor ACP backend not configured (cursor-agent not discovered).",
                detail=cfg.to_dict(),
            )
        if not cfg.acp_available():
            return AgentBackendAvailability(
                status=AGENT_AVAILABILITY_UNAVAILABLE,
                configured=True,
                message="cursor-agent executable not found on PATH; ACP server cannot start.",
                detail=cfg.to_dict(),
            )
        return AgentBackendAvailability(
            status=AGENT_AVAILABILITY_AVAILABLE,
            configured=True,
            message="Cursor Agent ACP transport ready (experimental).",
            detail=cfg.to_dict(),
        )

    def status_snapshot(self) -> dict[str, Any]:
        base = super().status_snapshot()
        base["config"] = self.config.to_dict()
        base["transport_health"] = self.health.to_dict()
        if self._last_telemetry is not None:
            base["last_acp_telemetry"] = self._last_telemetry.to_dict()
        return base

    # -- invocation ---------------------------------------------------------

    def invoke(self, request: AgentInvocationRequest) -> AgentInvocationResult:
        run = _AcpInvocationRun(self, request)
        result = run.execute()
        self._last_status = result.status
        self._last_telemetry = run.telemetry
        return result


class _AcpInvocationRun:
    """One bounded ACP lifecycle. Isolated so ``invoke`` stays declarative and
    cleanup is guaranteed in ``finally``."""

    def __init__(self, backend: CursorAcpBackend, request: AgentInvocationRequest) -> None:
        self.backend = backend
        self.request = request
        self.config = backend.config
        self.timeouts = backend.config.timeouts
        self.health = backend.health
        self.state = STATE_CREATED
        self.telemetry = AcpInvocationTelemetry()
        self.telemetry.transport_attempt_count = 1
        self._progress = deque(maxlen=_MAX_PROGRESS_EVENTS)
        self._seq = 0
        self._response_parts: list[str] = []
        self._response_bytes = 0
        self._truncated = False
        self._terminal_seen = False
        self._started = _now_iso()
        self._proc: Any = None
        self._conn: AcpConnection | None = None
        self._managed_result: ManagedProcessResult | None = None
        self._request_id = "req-" + uuid.uuid4().hex[:12]

    # -- helpers ------------------------------------------------------------

    def _set_state(self, state: str) -> None:
        self.state = state
        self.telemetry.invocation_state = state

    def _add_progress(self, event_type: str, summary: str | None) -> None:
        self._seq += 1
        now = _now_iso()
        event = AcpProgressEvent(
            sequence=self._seq,
            timestamp=now,
            event_type=event_type,
            summary=_bounded(summary),
            request_id=self._request_id,
        )
        self._progress.append(event)
        self.telemetry.progress_event_count = len(self._progress)
        self.telemetry.progress_events_total += 1
        if self.telemetry.first_progress_at is None:
            self.telemetry.first_progress_at = now
        self.telemetry.last_progress_at = now

    def _append_response_text(self, text: str) -> None:
        if not text:
            return
        encoded = len(text.encode("utf-8", errors="replace"))
        if self._response_bytes + encoded > self.backend._max_response_bytes:
            self._truncated = True
            return
        self._response_bytes += encoded
        self._response_parts.append(text)

    def _response_text(self) -> str:
        return "".join(self._response_parts)

    # -- execution ----------------------------------------------------------

    def execute(self) -> AgentInvocationResult:
        availability = self.backend.availability()
        if availability.status != AGENT_AVAILABILITY_AVAILABLE:
            status = (
                AGENT_INVOKE_BLOCKED_BY_CONFIGURATION
                if availability.status == AGENT_AVAILABILITY_NOT_CONFIGURED
                else AGENT_INVOKE_FAILED
            )
            self._set_state(STATE_PROTOCOL_ERROR)
            return self._result(status, error_message=availability.message)

        agent_ws = self._validated_agent_workspace()
        if agent_ws is None:
            self._set_state(STATE_PROTOCOL_ERROR)
            return self._result(
                AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
                error_message=(
                    "ACP backend requires an isolated agent workspace distinct from the "
                    "target workspace; refusing to start the server."
                ),
            )

        argv = self.config.acp_argv()
        env, env_diag = build_cursor_agent_safe_environment(self.backend._env_base)
        if not argv or env is None:
            self._set_state(STATE_PROTOCOL_ERROR)
            return self._result(
                AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
                error_message="ACP server executable or safe environment unavailable.",
            )

        result: AgentInvocationResult
        try:
            result = self._run_lifecycle(argv, str(agent_ws), env)
        finally:
            self._finalize_process()
        # Cleanup runs in the ``finally`` *after* the result is built, so reflect
        # the managed-process proof (and any cleanup-failure escalation) onto the
        # returned result before handing it back.
        return self._attach_finalization(result)

    def _attach_finalization(self, result: AgentInvocationResult) -> AgentInvocationResult:
        if self._managed_result is not None:
            result.managed_process_result = self._managed_result.to_dict()
            self.telemetry.managed_process_result = result.managed_process_result
        result.acp_invocation_state = self.state
        result.acp_telemetry = self.telemetry.to_dict()
        return result

    def _validated_agent_workspace(self) -> Path | None:
        raw = self.request.agent_workspace_path
        if not raw:
            return None
        agent_ws = Path(str(raw)).resolve()
        target = self.request.target_workspace_path
        if target and Path(str(target)).resolve() == agent_ws:
            return None
        agent_ws.mkdir(parents=True, exist_ok=True)
        return agent_ws

    def _run_lifecycle(
        self, argv: list[str], cwd: str, env: dict[str, str]
    ) -> AgentInvocationResult:
        # -- start server -----------------------------------------------
        self._set_state(STATE_SERVER_STARTING)
        self._proc = self.backend._process_factory(argv, cwd, env)
        try:
            self._proc.start()
        except Exception as exc:  # spawn failure
            self._set_state(STATE_PROTOCOL_ERROR)
            self.telemetry.retry_safe = True  # nothing was ever accepted
            self.health.record(OUTCOME_PROTOCOL_ERROR, detail="server_start_failed")
            return self._result(
                AGENT_INVOKE_FAILED, error_message=f"ACP server failed to start: {exc}"
            )
        self._conn = AcpConnection(self._proc)

        # -- handshake --------------------------------------------------
        self._set_state(STATE_HANDSHAKE_PENDING)
        handshake_start = time.perf_counter()
        init = self._request(
            ACP_METHOD_INITIALIZE,
            {"protocolVersion": 1, "clientCapabilities": {}},
            request_id=1,
            timeout=self.timeouts.handshake_seconds,
        )
        if init.kind != _RPC_OK:
            return self._handshake_failure(init)
        self.telemetry.handshake_duration_ms = round(
            (time.perf_counter() - handshake_start) * 1000, 3
        )
        protocol_version = _extract_protocol_version(init.result)
        self.telemetry.protocol_version = protocol_version
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            self._set_state(STATE_PROTOCOL_ERROR)
            self.health.record(OUTCOME_PROTOCOL_ERROR, detail="unsupported_protocol_version")
            return self._result(
                AGENT_INVOKE_FAILED,
                error_message=(
                    f"Unsupported ACP protocolVersion {protocol_version!r}; "
                    f"this spike speaks {sorted(SUPPORTED_PROTOCOL_VERSIONS)}."
                ),
            )
        self._set_state(STATE_READY)
        self.health.record(OUTCOME_HANDSHAKE_OK)

        # -- session/new ------------------------------------------------
        session = self._request(
            ACP_METHOD_SESSION_NEW,
            {"cwd": cwd, "mcpServers": []},
            request_id=2,
            timeout=self.timeouts.request_acceptance_seconds,
        )
        if session.kind != _RPC_OK:
            return self._session_setup_failure(session)
        self.telemetry.session_id = _extract_session_id(session.result)

        # -- enforce read-only plan mode (proposal-only invariant) ------
        self._enforce_plan_mode(session.result)

        # -- session/prompt (unique request id) -------------------------
        prompt_params = {
            "sessionId": self.telemetry.session_id,
            "prompt": [{"type": "text", "text": self.request.instruction_text}],
        }
        try:
            self._conn.send(ACP_METHOD_SESSION_PROMPT, prompt_params, request_id=self._request_id)
        except Exception as exc:
            # write failed -> server gone before it could accept -> provably unaccepted
            self._set_state(STATE_DISCONNECTED)
            self.telemetry.retry_safe = True
            self.health.record(OUTCOME_PROTOCOL_ERROR, detail="prompt_write_failed")
            return self._result(
                AGENT_INVOKE_FAILED,
                error_message=f"ACP prompt could not be submitted: {exc}",
            )
        self._set_state(STATE_REQUEST_SUBMITTED)
        self.telemetry.request_id = self._request_id
        self.telemetry.acp_request_count = 1

        return self._await_terminal()

    # -- prompt wait loop (PART E timeouts, F progress) ---------------------

    def _await_terminal(self) -> AgentInvocationResult:
        absolute_deadline = time.monotonic() + self.timeouts.absolute_request_seconds
        idle_deadline = time.monotonic() + self.timeouts.idle_no_progress_seconds
        assert self._conn is not None

        while True:
            now = time.monotonic()
            idle_remaining = idle_deadline - now
            absolute_remaining = absolute_deadline - now
            if absolute_remaining <= 0:
                return self._timeout(STATE_TIMED_OUT_TOTAL, OUTCOME_TOTAL_TIMEOUT)
            if idle_remaining <= 0:
                return self._timeout(STATE_TIMED_OUT_IDLE, OUTCOME_IDLE_TIMEOUT)

            read_timeout = min(idle_remaining, absolute_remaining)
            kind, payload = self._conn.read_message(read_timeout)

            if kind == MSG_TIMEOUT:
                continue  # loop re-evaluates which deadline actually fired
            if kind == MSG_EOF:
                return self._disconnected()
            if kind == MSG_MALFORMED:
                # A malformed line is a recoverable anomaly: note it and keep
                # reading. Idle liveness refreshes so a server that emits noise
                # then a real terminal still completes.
                self._add_progress("malformed_event", str(payload))
                idle_deadline = time.monotonic() + self.timeouts.idle_no_progress_seconds
                continue

            # kind == MSG_JSON
            message = payload
            method = message.get("method")
            msg_id = message.get("id")

            if method == ACP_METHOD_SESSION_UPDATE:
                self._handle_update(message.get("params") or {})
                idle_deadline = time.monotonic() + self.timeouts.idle_no_progress_seconds
                continue

            if msg_id == self._request_id:
                # Terminal for our prompt (success or error). Ignore duplicates.
                if self._terminal_seen:
                    continue
                self._terminal_seen = True
                if "error" in message:
                    return self._provider_error(message.get("error") or {})
                return self._terminal_success(message.get("result") or {})

            # Unrelated response/notification: refresh idle, keep waiting.
            idle_deadline = time.monotonic() + self.timeouts.idle_no_progress_seconds

    def _handle_update(self, params: dict[str, Any]) -> None:
        if self.telemetry.accepted_at is None:
            self.telemetry.accepted_at = _now_iso()
            self._set_state(STATE_ACCEPTED)
            self.health.record(OUTCOME_ACCEPTED)
        self._set_state(STATE_PROGRESS)
        kind, text = _classify_update(params)
        if kind == "message" and text:
            self._append_response_text(text)
            self._add_progress("agent_message_chunk", "model produced response text")
        else:
            self._add_progress(kind, text)

    # -- terminal outcomes --------------------------------------------------

    def _terminal_success(self, result: dict[str, Any]) -> AgentInvocationResult:
        # Some servers may also carry final text on the terminal result.
        trailing = _extract_result_text(result)
        if trailing and not self._response_parts:
            self._append_response_text(trailing)
        stop_reason = result.get("stopReason") or result.get("stop_reason") or "end_turn"
        self.telemetry.terminal_event = f"result:{stop_reason}"
        self.telemetry.completed_at = _now_iso()
        self.telemetry.model_turns = 1
        response_text = self._response_text().strip()
        self.telemetry.response_bytes = self._response_bytes
        if response_text:
            self._set_state(STATE_COMPLETED)
            self.telemetry.usable_responses = 1
            self.health.record(OUTCOME_USABLE_COMPLETION)
            return self._result(AGENT_INVOKE_SUCCESS, response_text=response_text)
        self._set_state(STATE_COMPLETED)
        self.health.record(OUTCOME_EMPTY_RESPONSE)
        return self._result(
            AGENT_INVOKE_EMPTY_SUCCESS,
            error_message="ACP turn completed but produced no usable response text.",
        )

    def _provider_error(self, error: dict[str, Any]) -> AgentInvocationResult:
        self._set_state(STATE_PROVIDER_ERROR)
        self.telemetry.terminal_event = "error"
        self.telemetry.completed_at = _now_iso()
        self.health.record(OUTCOME_PROVIDER_ERROR)
        message = error.get("message") if isinstance(error, dict) else str(error)
        return self._result(
            AGENT_INVOKE_FAILED, error_message=f"ACP provider error: {_bounded(str(message))}"
        )

    def _handshake_failure(self, rpc: "_RpcResult") -> AgentInvocationResult:
        if rpc.kind == _RPC_EOF:
            self._set_state(STATE_DISCONNECTED)
            self.telemetry.retry_safe = True  # never accepted (handshake stage)
            self.health.record(OUTCOME_PROTOCOL_ERROR, detail="disconnect_during_handshake")
            return self._result(
                AGENT_INVOKE_FAILED, error_message="ACP server disconnected during handshake."
            )
        if rpc.kind == _RPC_TIMEOUT:
            self._set_state(STATE_TIMED_OUT_TOTAL)
            self.telemetry.retry_safe = True
            self.health.record(OUTCOME_TOTAL_TIMEOUT, detail="handshake_timeout")
            return self._result(
                AGENT_INVOKE_TIMEOUT, error_message="ACP handshake timed out."
            )
        self._set_state(STATE_PROTOCOL_ERROR)
        self.telemetry.retry_safe = True
        self.health.record(OUTCOME_PROTOCOL_ERROR, detail="handshake_error")
        return self._result(
            AGENT_INVOKE_FAILED, error_message=f"ACP handshake failed: {rpc.detail}"
        )

    def _session_setup_failure(self, rpc: "_RpcResult") -> AgentInvocationResult:
        # session/new failed: the prompt was never submitted -> provably unaccepted.
        self.telemetry.retry_safe = True
        if rpc.kind == _RPC_EOF:
            self._set_state(STATE_DISCONNECTED)
            self.health.record(OUTCOME_PROTOCOL_ERROR, detail="disconnect_before_acceptance")
            return self._result(
                AGENT_INVOKE_FAILED,
                error_message="ACP server disconnected before the session was created.",
            )
        if rpc.kind == _RPC_TIMEOUT:
            self._set_state(STATE_TIMED_OUT_TOTAL)
            self.health.record(OUTCOME_TOTAL_TIMEOUT, detail="session_new_timeout")
            return self._result(
                AGENT_INVOKE_TIMEOUT, error_message="ACP session/new timed out."
            )
        self._set_state(STATE_PROTOCOL_ERROR)
        self.health.record(OUTCOME_PROTOCOL_ERROR, detail="session_new_error")
        return self._result(
            AGENT_INVOKE_FAILED, error_message=f"ACP session/new failed: {rpc.detail}"
        )

    def _disconnected(self) -> AgentInvocationResult:
        # A disconnect *after* submit cannot prove non-acceptance -> uncertain.
        self._set_state(STATE_DISCONNECTED)
        if self.state in _PRE_SUBMIT_STATES or self.telemetry.request_id is None:
            self.telemetry.retry_safe = True
            self.health.record(OUTCOME_PROTOCOL_ERROR, detail="disconnect_before_submit")
            return self._result(
                AGENT_INVOKE_FAILED,
                error_message="ACP server disconnected before the request was submitted.",
            )
        self._set_state(STATE_UNCERTAIN_COMPLETION)
        self.telemetry.retry_safe = False
        self.telemetry.terminal_event = "disconnected_after_acceptance"
        self.health.record(OUTCOME_UNCERTAIN_COMPLETION, detail="disconnect_after_submit")
        return self._result(
            AGENT_INVOKE_TIMEOUT,
            error_message=(
                "ACP server disconnected after the request was submitted; completion is "
                "uncertain. No automatic retry."
            ),
        )

    def _timeout(self, state: str, outcome: str) -> AgentInvocationResult:
        # A timeout after submit is uncertain: request cancellation, then verify
        # cleanup. Never auto-retried (PART E.20/21).
        self._set_state(STATE_CANCELLATION_REQUESTED)
        self._request_cancel()
        self._set_state(state)
        self.telemetry.retry_safe = False
        self.telemetry.terminal_event = state
        self.health.record(outcome)
        # The uncertain-completion signal is what forbids auto-retry downstream.
        self.health.record(OUTCOME_UNCERTAIN_COMPLETION, detail=state)
        self._set_state(STATE_UNCERTAIN_COMPLETION)
        return self._result(
            AGENT_INVOKE_TIMEOUT,
            error_message=(
                f"ACP request {state}; cancellation requested and completion is uncertain. "
                "No automatic retry."
            ),
        )

    def _enforce_plan_mode(self, session_result: dict[str, Any]) -> None:
        """Force the ACP session into read-only ``plan`` mode so the agent only
        *proposes* (never executes) — the ACP analogue of the one-shot's
        ``--mode plan``. Best-effort: a server that does not support
        ``session/set_mode`` leaves the mode unchanged and the fact is recorded
        honestly (``plan_mode_enforced=False``) rather than silently assumed."""
        modes = session_result.get("modes") if isinstance(session_result, dict) else None
        if not isinstance(modes, dict):
            self.telemetry.plan_mode_enforced = False
            return
        current = modes.get("currentModeId") or modes.get("current_mode_id")
        self.telemetry.session_mode_before = current
        available = {
            m.get("id")
            for m in (modes.get("availableModes") or [])
            if isinstance(m, dict)
        }
        if ACP_MODE_PLAN not in available and current != ACP_MODE_PLAN:
            self.telemetry.plan_mode_enforced = False
            return
        if current == ACP_MODE_PLAN:
            self.telemetry.session_mode_enforced = ACP_MODE_PLAN
            self.telemetry.plan_mode_enforced = True
            return
        res = self._request(
            ACP_METHOD_SESSION_SET_MODE,
            {"sessionId": self.telemetry.session_id, "modeId": ACP_MODE_PLAN},
            request_id=3,
            timeout=self.timeouts.request_acceptance_seconds,
        )
        if res.kind == _RPC_OK:
            self.telemetry.session_mode_enforced = ACP_MODE_PLAN
            self.telemetry.plan_mode_enforced = True
        else:
            self.telemetry.plan_mode_enforced = False

    def _request_cancel(self) -> None:
        if self._conn is None or self.telemetry.session_id is None:
            return
        try:
            self._conn.send(
                ACP_METHOD_SESSION_CANCEL, {"sessionId": self.telemetry.session_id}
            )
        except Exception:
            pass

    # -- JSON-RPC request/response ------------------------------------------

    def _request(
        self, method: str, params: dict[str, Any], *, request_id: Any, timeout: float
    ) -> "_RpcResult":
        assert self._conn is not None
        try:
            self._conn.send(method, params, request_id=request_id)
        except Exception as exc:
            return _RpcResult(_RPC_EOF, detail=f"send failed: {exc}")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _RpcResult(_RPC_TIMEOUT)
            kind, payload = self._conn.read_message(remaining)
            if kind == MSG_TIMEOUT:
                return _RpcResult(_RPC_TIMEOUT)
            if kind == MSG_EOF:
                return _RpcResult(_RPC_EOF)
            if kind == MSG_MALFORMED:
                # tolerate a malformed line before the response we're waiting on
                continue
            message = payload
            if message.get("method") == ACP_METHOD_SESSION_UPDATE:
                # progress can precede a setup response; refresh nothing here.
                continue
            if message.get("id") == request_id:
                if "error" in message:
                    return _RpcResult(_RPC_ERROR, detail=_bounded(str(message.get("error"))))
                return _RpcResult(_RPC_OK, result=message.get("result") or {})
            # unrelated message: keep reading

    # -- cleanup ------------------------------------------------------------

    def _finalize_process(self) -> None:
        if self._proc is None:
            return
        try:
            if self.state == STATE_COMPLETED and self._proc.poll() is None:
                # graceful shutdown of a healthy server
                self._managed_result = self._proc.terminate(reason=TERMINATION_CANCELLED)
            elif self._proc.poll() is not None:
                self._proc.finish(reason=TERMINATION_COMPLETED)
                self._managed_result = self._proc.result()
            else:
                reason = (
                    TERMINATION_HARD_TIMEOUT
                    if self.state in (STATE_TIMED_OUT_IDLE, STATE_TIMED_OUT_TOTAL)
                    else TERMINATION_CANCELLED
                )
                self._managed_result = self._proc.terminate(reason=reason)
        except Exception:
            try:
                self._managed_result = self._proc.result()
            except Exception:
                self._managed_result = None

        if self._managed_result is not None:
            self.telemetry.managed_process_result = self._managed_result.to_dict()
            if not self._managed_result.cleanup_proven:
                # Circuit breaker: a leaked tree latches unhealthy and forbids
                # auto-retry until explicit operator recovery (PART A.6, I.37).
                self.health.record(OUTCOME_CLEANUP_FAILURE)
                if self.state != STATE_CLEANUP_FAILED:
                    self._set_state(STATE_CLEANUP_FAILED)

    # -- canonical result ---------------------------------------------------

    def _result(
        self,
        status: str,
        *,
        response_text: str | None = None,
        error_message: str | None = None,
    ) -> AgentInvocationResult:
        self.telemetry.progress_events = [e.to_dict() for e in self._progress]
        return AgentInvocationResult(
            status=status,
            response_text=response_text,
            raw_stdout=None,
            raw_stderr=(self._proc.captured_stderr() if self._proc is not None else None),
            exit_code=(self._managed_result.exit_code if self._managed_result else None),
            model_label="cursor-agent-default",
            transport_label=BACKEND_ID_CURSOR_ACP,
            started_at=self._started,
            completed_at=_now_iso(),
            error_message=error_message,
            full_instruction_length=len(self.request.instruction_text),
            stdout_length=self._response_bytes,
            transport_kind=BACKEND_ID_CURSOR_ACP,
            acp_request_id=self.telemetry.request_id,
            acp_session_id=self.telemetry.session_id,
            acp_protocol_version=self.telemetry.protocol_version,
            acp_invocation_state=self.state,
            acp_telemetry=self.telemetry.to_dict(),
            managed_process_result=(
                self._managed_result.to_dict() if self._managed_result else None
            ),
        )


# -- internal JSON-RPC request result ----------------------------------------
_RPC_OK = "ok"
_RPC_ERROR = "error"
_RPC_TIMEOUT = "timeout"
_RPC_EOF = "eof"


@dataclass
class _RpcResult:
    kind: str
    result: dict[str, Any] = field(default_factory=dict)
    detail: str | None = None


# ---------------------------------------------------------------------------
# Tolerant protocol extraction (documented unknowns -> defensive parsing)
# ---------------------------------------------------------------------------


def _extract_protocol_version(result: dict[str, Any]) -> int | None:
    for key in ("protocolVersion", "protocol_version"):
        value = result.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def _extract_session_id(result: dict[str, Any]) -> str | None:
    for key in ("sessionId", "session_id", "id"):
        value = result.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _classify_update(params: dict[str, Any]) -> tuple[str, str | None]:
    """Classify a ``session/update`` notification into (kind, bounded_text).

    ``message`` -> agent response text (accumulated into the canonical response).
    Everything else (thoughts, tool calls, plans) -> progress only; the summary
    is bounded and internal reasoning content is deliberately not retained
    (PART F.24).
    """
    update = params.get("update")
    if not isinstance(update, dict):
        # Some shapes may put the content directly on params.
        update = params
    kind = (
        update.get("sessionUpdate")
        or update.get("type")
        or update.get("kind")
        or "update"
    )
    text = _extract_content_text(update.get("content"))
    kind_l = str(kind).lower()
    if "message" in kind_l:
        return ("message", text)
    if "thought" in kind_l or "reason" in kind_l:
        return ("agent_thought", "model is reasoning")
    if "tool" in kind_l:
        tool = update.get("title") or update.get("toolName") or update.get("kind")
        return ("tool_call", _bounded(str(tool) if tool else "tool call"))
    if "plan" in kind_l:
        return ("plan", "model updated its plan")
    return (str(kind), _bounded(text) if text else "progress")


def _extract_content_text(content: Any) -> str | None:
    if content is None:
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        if isinstance(content.get("text"), str):
            return content["text"]
        # nested {content: {...}}
        return _extract_content_text(content.get("content"))
    if isinstance(content, list):
        parts = [_extract_content_text(item) for item in content]
        joined = "".join(p for p in parts if p)
        return joined or None
    return None


def _extract_result_text(result: dict[str, Any]) -> str | None:
    for key in ("text", "content", "message", "output"):
        if key in result:
            text = _extract_content_text(result.get(key))
            if text:
                return text
    return None


__all__ = [
    "BACKEND_ID_CURSOR_ACP",
    "BACKEND_ID_CURSOR_ONESHOT",
    "TRANSPORT_LABEL_ACP",
    "TRANSPORT_LABEL_ONESHOT",
    "CURSOR_TRANSPORT_ENV",
    "TRANSPORT_ACP",
    "TRANSPORT_ONESHOT",
    "DEFAULT_TRANSPORT",
    "select_transport",
    "ACP_INVOCATION_STATES",
    "STATE_CREATED",
    "STATE_SERVER_STARTING",
    "STATE_HANDSHAKE_PENDING",
    "STATE_READY",
    "STATE_REQUEST_SUBMITTED",
    "STATE_ACCEPTED",
    "STATE_RUNNING",
    "STATE_PROGRESS",
    "STATE_RESPONSE_READY",
    "STATE_COMPLETED",
    "STATE_PROVIDER_ERROR",
    "STATE_PROTOCOL_ERROR",
    "STATE_DISCONNECTED",
    "STATE_CANCELLATION_REQUESTED",
    "STATE_CANCELLED",
    "STATE_TIMED_OUT_IDLE",
    "STATE_TIMED_OUT_TOTAL",
    "STATE_UNCERTAIN_COMPLETION",
    "STATE_CLEANUP_FAILED",
    "ACP_METHOD_INITIALIZE",
    "ACP_METHOD_SESSION_NEW",
    "ACP_METHOD_SESSION_PROMPT",
    "ACP_METHOD_SESSION_CANCEL",
    "ACP_METHOD_SESSION_UPDATE",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "AcpTimeouts",
    "AcpProgressEvent",
    "AcpInvocationTelemetry",
    "AcpConnection",
    "CursorAcpConfig",
    "CursorAcpBackend",
    "MSG_EOF",
    "MSG_TIMEOUT",
    "MSG_MALFORMED",
    "MSG_JSON",
]
