"""Model-agnostic agent backend abstraction v0 (slice ADMISSIBLE_RUN_032).

The high-autonomy governed loop used to depend on the Cursor GUI voluntarily
noticing ``.admissible/next-agent-instruction.md`` and writing
``.admissible/agent-response.md`` back. That is only *semi-autonomous*: there
is no agent-side loop Admissible actually drives — a human still has to keep
Cursor pointed at the bridge files.

This module introduces a model-agnostic ``AgentBackend`` so the controller can
call an agent backend through one common interface, with Cursor CLI/headless as
the first concrete callable target and a deterministic fixture backend for
tests. It keeps the existing ``AgentTransport`` / file bridge fully compatible:
a ``FileBridgeAgentBackend`` wraps the legacy transport and reports honestly
that it is external/manual/semi-autonomous, and ``CallableBackendTransport``
adapts any callable backend onto the existing tick-driven transport interface
so the high-autonomy state machine is reused unchanged.

Core principle (unchanged): the agent/model *proposes*; Admissible decides what
may be admitted; only Admissible's bounded executor writes to the *target*
workspace. A backend must never receive direct write authority over the target
workspace:

- ``target_workspace_path``  -- where admitted writes are applied by Admissible.
- ``agent_workspace_path``   -- an isolated workspace used only to hand the
  instruction to the agent and (optionally) receive its structured proposal.

Hard constraints honored here:

- Does not call any model provider in tests, and never at import time.
- Never executes a real Cursor CLI in unit tests (subprocess is injectable /
  mockable; the backend is disabled unless explicitly configured).
- Adds no arbitrary shell execution for model proposals: the Cursor CLI backend
  runs a *configured* argv with ``shell=False``, a timeout, a size cap, a
  sanitized environment, and ``cwd`` set to the agent workspace — never the
  target workspace.
- Never lets a backend mutate the target workspace directly; response text is
  always routed back through the existing ingest/admission/bounded-executor
  path by the controller.
- Never weakens admission or content guards, never makes high-autonomy default,
  never auto-approves human-critical actions.

See docs/admissible-model-agnostic-agent-transport.md.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from admissible.agent_transport import (
    TRANSPORT_STATUS_ERROR,
    TRANSPORT_STATUS_IDLE,
    TRANSPORT_STATUS_INSTRUCTION_WRITTEN,
    TRANSPORT_STATUS_RESPONSE_CONSUMED,
    TRANSPORT_STATUS_RESPONSE_DETECTED,
    TRANSPORT_STATUS_WAITING,
    AgentTransport,
    AgentTransportReadResult,
)

# -- invocation result status codes ------------------------------------------
AGENT_INVOKE_SUCCESS = "success"
AGENT_INVOKE_UNAVAILABLE = "unavailable"
AGENT_INVOKE_TIMEOUT = "timeout"
AGENT_INVOKE_FAILED = "failed"
AGENT_INVOKE_MALFORMED = "malformed"
AGENT_INVOKE_EMPTY_SUCCESS = "empty_success"
AGENT_INVOKE_BLOCKED_BY_CONFIGURATION = "blocked_by_configuration"

AGENT_INVOKE_STATUS_CODES = frozenset(
    {
        AGENT_INVOKE_SUCCESS,
        AGENT_INVOKE_UNAVAILABLE,
        AGENT_INVOKE_TIMEOUT,
        AGENT_INVOKE_FAILED,
        AGENT_INVOKE_MALFORMED,
        AGENT_INVOKE_EMPTY_SUCCESS,
        AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    }
)

# Statuses that mean "the loop cannot make progress with this backend right now".
# The controller pauses/halts on these instead of spinning; they never
# auto-advance a turn or re-invoke without an explicit operator retry.
AGENT_INVOKE_TERMINAL_STATUSES = frozenset(
    {
        AGENT_INVOKE_UNAVAILABLE,
        AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
        AGENT_INVOKE_TIMEOUT,
        AGENT_INVOKE_FAILED,
        AGENT_INVOKE_MALFORMED,
        AGENT_INVOKE_EMPTY_SUCCESS,
    }
)

# -- backend availability codes ----------------------------------------------
AGENT_AVAILABILITY_AVAILABLE = "available"
AGENT_AVAILABILITY_NOT_CONFIGURED = "not_configured"
AGENT_AVAILABILITY_UNAVAILABLE = "unavailable"
AGENT_AVAILABILITY_UNSUPPORTED = "unsupported"
AGENT_AVAILABILITY_EXTERNAL = "external_manual"

# -- backend ids -------------------------------------------------------------
BACKEND_ID_FIXTURE = "fixture"
BACKEND_ID_FILE_BRIDGE = "file_bridge"
BACKEND_ID_CURSOR_CLI = "cursor_cli"

DEFAULT_MAX_OUTPUT_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 120.0

# -- Cursor CLI discovery/config environment variables -----------------------
# Distinct from the Cursor GUI launcher used by cursor_bridge.open_workspace_in
# _cursor (ADMISSIBLE_CURSOR_LAUNCHER): those open the GUI, these drive a
# headless CLI. Nothing here hard-codes Cursor CLI syntax — the argv template is
# operator-supplied so the backend never *guesses* an unverified command shape.
CURSOR_CLI_COMMAND_ENV = "ADMISSIBLE_CURSOR_CLI_COMMAND"
CURSOR_CLI_ARGS_ENV = "ADMISSIBLE_CURSOR_CLI_ARGS"
CURSOR_CLI_VERSION_ARGS_ENV = "ADMISSIBLE_CURSOR_CLI_VERSION_ARGS"
CURSOR_CLI_INPUT_MODE_ENV = "ADMISSIBLE_CURSOR_CLI_INPUT_MODE"
CURSOR_CLI_OUTPUT_MODE_ENV = "ADMISSIBLE_CURSOR_CLI_OUTPUT_MODE"
CURSOR_CLI_MODEL_LABEL_ENV = "ADMISSIBLE_CURSOR_CLI_MODEL_LABEL"

INPUT_MODE_INSTRUCTION_FILE = "instruction_file"
INPUT_MODE_STDIN = "stdin"
INPUT_MODE_PROMPT_ARG = "prompt_arg"
INPUT_MODE_FILE_POINTER_ALWAYS = "file_pointer_always"
OUTPUT_MODE_STDOUT = "stdout"
OUTPUT_MODE_RESPONSE_FILE = "response_file"

PROMPT_MODE_INLINE = "inline"
PROMPT_MODE_FILE_POINTER = "file_pointer"

# Placeholders the operator may reference in the argv template. Substituted with
# absolute paths that always live inside the *agent* workspace, or (for
# ``{prompt}``) with the instruction text as a single argv element (shell=False,
# so it is never shell-interpreted).
PLACEHOLDER_INSTRUCTION_FILE = "{instruction_file}"
PLACEHOLDER_RESPONSE_FILE = "{response_file}"
PLACEHOLDER_AGENT_WORKSPACE = "{agent_workspace}"
PLACEHOLDER_PROMPT = "{prompt}"

AGENT_BRIDGE_SUBDIR = ".admissible"
AGENT_INSTRUCTION_FILENAME = "next-agent-instruction.md"
AGENT_RESPONSE_FILENAME = "agent-response.md"

# -- Cursor Agent CLI safe preset (slice ADMISSIBLE_RUN_033) -----------------
# The real local Cursor Agent CLI is ``cursor-agent`` (NOT ``cursor agent`` — the
# ``cursor`` command is the IDE wrapper and does not expose the real Agent CLI).
# Admissible only ever drives it in read-only *planning* mode: it analyzes and
# proposes, it does not edit. The model still proposes; only Admissible's bounded
# executor writes to the target workspace.
CURSOR_AGENT_CLI_COMMAND = "cursor-agent"
CURSOR_AGENT_CLI_SAFE_ARGS: tuple[str, ...] = (
    "--print",
    "--output-format",
    "text",
    "--mode",
    "plan",
    "--workspace",
    PLACEHOLDER_AGENT_WORKSPACE,
    "--trust",
    PLACEHOLDER_PROMPT,
)
CURSOR_AGENT_CLI_MODEL_LABEL = "cursor-agent-default"

# Command basenames recognised as the real Cursor Agent CLI vs the IDE wrapper.
_CURSOR_AGENT_COMMAND_NAMES = frozenset(
    {"cursor-agent", "cursor-agent.exe", "cursor-agent.cmd"}
)
_CURSOR_IDE_COMMAND_NAMES = frozenset({"cursor", "cursor.exe", "cursor.cmd"})

# Flags that must never appear in a Cursor CLI argv template — they grant
# unsupervised write/execute authority or disable sandboxing.
_UNSAFE_CURSOR_FLAGS = ("--force", "--yolo")

# Generic prompt-argument backends may use this threshold to avoid oversized
# command lines. Cursor Agent does not use the threshold: its stable contract is
# always a single-line file-pointer adapter argv element.
PROMPT_ARG_MAX_CHARS = 6000

# Characters that must never appear in the Cursor Agent ``{prompt}`` adapter.
# Windows resolves ``cursor-agent`` to ``cursor-agent.CMD``, which forwards through
# PowerShell ``-File`` and ``node.exe index.js $args`` — multiline argv values are
# split or dropped at that boundary, producing exit 0 with empty stdout.
_CURSOR_AGENT_ADAPTER_FORBIDDEN_CHARS = ("\r", "\n", "\x00", "\t")


def build_cursor_agent_file_pointer_adapter(instruction_file: Path) -> str:
    """Build the single-line Cursor Agent file-pointer ``{prompt}`` adapter."""
    path = str(instruction_file.resolve())
    return (
        f'Read the complete governed instruction from the file at "{path}". '
        "Return the complete proposed response directly to stdout. "
        "Do not write or modify any file. "
        "Do not write .admissible/agent-response.md. "
        "Include all requested ADMISSIBLE_STRUCTURED_OPERATION blocks directly in stdout. "
        "Follow the response format in the instruction file."
    )


def validate_cursor_agent_file_pointer_adapter(adapter: str) -> str | None:
    """Return a configuration error when the adapter violates the single-line contract."""
    for char in _CURSOR_AGENT_ADAPTER_FORBIDDEN_CHARS:
        if char in adapter:
            label = {"\r": "CR", "\n": "LF", "\x00": "NUL", "\t": "TAB"}[char]
            return (
                "Cursor Agent file-pointer adapter must be exactly one argv line "
                f"without {label}; refusing to invoke."
            )
    line_count = len(adapter.splitlines()) if adapter else 0
    if line_count != 1:
        return (
            "Cursor Agent file-pointer adapter must be exactly one argv line "
            f"(got {line_count}); refusing to invoke."
        )
    return None


def cursor_agent_adapter_diagnostics(adapter: str) -> dict[str, Any]:
    """Safe diagnostics for a Cursor Agent file-pointer adapter (no secrets)."""
    contains_crlf = any(ch in adapter for ch in ("\r", "\n"))
    if not adapter:
        line_count = 0
    elif contains_crlf:
        line_count = len(adapter.splitlines())
    else:
        line_count = 1
    return {
        "adapter_prompt_length": len(adapter),
        "adapter_line_count": line_count,
        "adapter_contains_crlf": contains_crlf,
        "adapter_sha256": _sha256_text(adapter) if adapter else None,
    }

# Environment variables passed through to a spawned Cursor CLI. Deliberately a
# small OS-essential allowlist so provider keys and unrelated secrets in the
# parent environment are never leaked to the child process.
_ENV_PRESERVE_CANONICAL: tuple[str, ...] = (
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "SystemDrive",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "HOME",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
)

_ENV_CANONICAL_BY_LOWER = {name.lower(): name for name in _ENV_PRESERVE_CANONICAL}

# Path-like variables validated after %NAME% expansion (HOMEPATH may stay drive-relative).
_PATH_LIKE_ENV_VARS = frozenset(
    {
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "TEMP",
        "TMP",
    }
)

_DRIVE_LETTER_VARS = frozenset({"SystemDrive", "HOMEDRIVE"})

_WIN_PERCENT_REF = re.compile(r"%([^%]+)%")

_ENV_EXPANSION_MAX_ROUNDS = 64
_MAX_ENV_VALUE_LEN = 8192

# Legacy alias kept for tests that referenced the old name.
_ENV_PASSTHROUGH_ALLOWLIST = _ENV_PRESERVE_CANONICAL


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Request / result value objects
# ---------------------------------------------------------------------------


@dataclass
class AgentInvocationRequest:
    """One instruction to hand to an agent backend.

    ``target_workspace_path`` is passed for context only — a backend must never
    write there directly. Agent output is written/executed only through
    Admissible's ingest + bounded executor path.
    """

    instruction_text: str
    session_id: str | None = None
    turn_number: int | None = None
    instruction_id: str | None = None
    target_workspace_path: str | None = None
    agent_workspace_path: str | None = None
    constraints: dict[str, Any] = field(default_factory=dict)
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_text": self.instruction_text,
            "session_id": self.session_id,
            "turn_number": self.turn_number,
            "instruction_id": self.instruction_id,
            "target_workspace_path": self.target_workspace_path,
            "agent_workspace_path": self.agent_workspace_path,
            "constraints": dict(self.constraints),
            "max_output_bytes": self.max_output_bytes,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class AgentInvocationResult:
    """Structured outcome of one backend invocation."""

    status: str
    response_text: str | None = None
    raw_stdout: str | None = None
    raw_stderr: str | None = None
    exit_code: int | None = None
    model_label: str | None = None
    transport_label: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    prompt_mode: str | None = None
    instruction_file_path: str | None = None
    instruction_sha256: str | None = None
    adapter_prompt_length: int | None = None
    adapter_line_count: int | None = None
    adapter_contains_crlf: bool | None = None
    adapter_sha256: str | None = None
    full_instruction_length: int | None = None
    stdout_length: int | None = None
    invocation_duration_ms: float | None = None
    environment_status: str | None = None
    environment_platform: str | None = None
    environment_variable_names: list[str] | None = None
    unresolved_environment_variables: list[str] | None = None
    cursor_profile_environment_present: bool | None = None
    program_data_path_present: bool | None = None
    environment_paths: dict[str, str] | None = None

    @property
    def ok(self) -> bool:
        return self.status == AGENT_INVOKE_SUCCESS and bool(
            (self.response_text or "").strip()
        )

    @property
    def is_terminal_block(self) -> bool:
        """True when the backend cannot currently make progress (pause, not spin)."""
        return self.status in AGENT_INVOKE_TERMINAL_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "response_text": self.response_text,
            "raw_stdout": self.raw_stdout,
            "raw_stderr": self.raw_stderr,
            "exit_code": self.exit_code,
            "model_label": self.model_label,
            "transport_label": self.transport_label,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error_message": self.error_message,
            "prompt_mode": self.prompt_mode,
            "instruction_file_path": self.instruction_file_path,
            "instruction_sha256": self.instruction_sha256,
            "adapter_prompt_length": self.adapter_prompt_length,
            "adapter_line_count": self.adapter_line_count,
            "adapter_contains_crlf": self.adapter_contains_crlf,
            "adapter_sha256": self.adapter_sha256,
            "full_instruction_length": self.full_instruction_length,
            "stdout_length": self.stdout_length,
            "invocation_duration_ms": self.invocation_duration_ms,
            "environment_status": self.environment_status,
            "environment_platform": self.environment_platform,
            "environment_variable_names": (
                list(self.environment_variable_names)
                if self.environment_variable_names is not None
                else None
            ),
            "unresolved_environment_variables": (
                list(self.unresolved_environment_variables)
                if self.unresolved_environment_variables is not None
                else None
            ),
            "cursor_profile_environment_present": self.cursor_profile_environment_present,
            "program_data_path_present": self.program_data_path_present,
            "environment_paths": (
                dict(self.environment_paths) if self.environment_paths is not None else None
            ),
        }


# -- durable callable-invocation record (slice ADMISSIBLE_RUN_034) -----------
# A callable backend's response must survive controller/transport reconstruction
# between HTTP ticks. The in-memory transport is NOT a safe home for a pending
# response; this record is persisted in the run state so the browser/server
# lifecycle (a fresh controller per request or after a restart) can still ingest
# the response exactly once.
INVOCATION_STATUS_INVOKING = "invoking"
INVOCATION_STATUS_RESPONSE_READY = "response_ready"
INVOCATION_STATUS_CONSUMED = "consumed"
INVOCATION_STATUS_TIMEOUT = "timeout"
INVOCATION_STATUS_FAILED = "failed"
INVOCATION_STATUS_MALFORMED = "malformed"
INVOCATION_STATUS_EMPTY_SUCCESS = "empty_success"

# Display-only callable-backend step labels (never shown for the file bridge).
CALLABLE_STEP_INVOKING = "invoking_agent"
CALLABLE_STEP_RESPONSE_READY = "response_ready"
CALLABLE_STEP_INGESTING = "ingesting_response"
CALLABLE_STEP_CONSUMED = "response_consumed"

# Maps a raw invocation result status onto the persisted-record status.
_RESULT_TO_RECORD_STATUS = {
    AGENT_INVOKE_SUCCESS: INVOCATION_STATUS_RESPONSE_READY,
    AGENT_INVOKE_TIMEOUT: INVOCATION_STATUS_TIMEOUT,
    AGENT_INVOKE_FAILED: INVOCATION_STATUS_FAILED,
    AGENT_INVOKE_MALFORMED: INVOCATION_STATUS_MALFORMED,
    AGENT_INVOKE_EMPTY_SUCCESS: INVOCATION_STATUS_EMPTY_SUCCESS,
    AGENT_INVOKE_UNAVAILABLE: INVOCATION_STATUS_FAILED,
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION: INVOCATION_STATUS_FAILED,
}

_SUMMARY_MAX_CHARS = 500


def _summary(text: str | None) -> str | None:
    if not text:
        return None
    text = text.strip()
    return text if len(text) <= _SUMMARY_MAX_CHARS else text[:_SUMMARY_MAX_CHARS] + "…"


@dataclass
class AgentInvocationRecord:
    """Durable, persisted record of one callable-backend invocation.

    Stored in the run state (not on the in-memory transport) so a response
    dispatched on tick N can be ingested on tick N+1 even after the controller,
    backend, and transport are reconstructed. Exactly-once is enforced by
    ``invocation_id`` + ``response_sha256``.
    """

    invocation_id: str
    instruction_id: str | None
    backend_id: str
    session_id: str | None
    turn_number: int | None
    status: str
    response_text: str | None = None
    response_sha256: str | None = None
    stdout_summary: str | None = None
    stderr_summary: str | None = None
    exit_code: int | None = None
    error_message: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    consumed_at: str | None = None
    prompt_mode: str | None = None
    instruction_file_path: str | None = None
    instruction_sha256: str | None = None
    adapter_prompt_length: int | None = None
    adapter_line_count: int | None = None
    adapter_contains_crlf: bool | None = None
    adapter_sha256: str | None = None
    full_instruction_length: int | None = None
    stdout_length: int | None = None
    invocation_duration_ms: float | None = None
    environment_status: str | None = None
    environment_platform: str | None = None
    environment_variable_names: list[str] | None = None
    unresolved_environment_variables: list[str] | None = None
    cursor_profile_environment_present: bool | None = None
    program_data_path_present: bool | None = None
    environment_paths: dict[str, str] | None = None
    attempt_number: int = 1
    retry_of_invocation_id: str | None = None
    estimated_cost: str = "unknown"
    operator_retry_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "instruction_id": self.instruction_id,
            "backend_id": self.backend_id,
            "session_id": self.session_id,
            "turn_number": self.turn_number,
            "status": self.status,
            "response_text": self.response_text,
            "response_sha256": self.response_sha256,
            "stdout_summary": self.stdout_summary,
            "stderr_summary": self.stderr_summary,
            "exit_code": self.exit_code,
            "error_message": self.error_message,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "consumed_at": self.consumed_at,
            "prompt_mode": self.prompt_mode,
            "instruction_file_path": self.instruction_file_path,
            "instruction_sha256": self.instruction_sha256,
            "adapter_prompt_length": self.adapter_prompt_length,
            "adapter_line_count": self.adapter_line_count,
            "adapter_contains_crlf": self.adapter_contains_crlf,
            "adapter_sha256": self.adapter_sha256,
            "full_instruction_length": self.full_instruction_length,
            "stdout_length": self.stdout_length,
            "invocation_duration_ms": self.invocation_duration_ms,
            "environment_status": self.environment_status,
            "environment_platform": self.environment_platform,
            "environment_variable_names": (
                list(self.environment_variable_names)
                if self.environment_variable_names is not None
                else None
            ),
            "unresolved_environment_variables": (
                list(self.unresolved_environment_variables)
                if self.unresolved_environment_variables is not None
                else None
            ),
            "cursor_profile_environment_present": self.cursor_profile_environment_present,
            "program_data_path_present": self.program_data_path_present,
            "environment_paths": (
                dict(self.environment_paths) if self.environment_paths is not None else None
            ),
            "attempt_number": self.attempt_number,
            "retry_of_invocation_id": self.retry_of_invocation_id,
            "estimated_cost": self.estimated_cost,
            "operator_retry_count": self.operator_retry_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AgentInvocationRecord | None":
        if not data:
            return None
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


def build_invocation_record(
    result: AgentInvocationResult,
    *,
    backend_id: str,
    instruction_id: str | None,
    session_id: str | None,
    turn_number: int | None,
    invocation_id: str | None = None,
    attempt_number: int = 1,
    retry_of_invocation_id: str | None = None,
    estimated_cost: str = "unknown",
    operator_retry_count: int = 0,
) -> AgentInvocationRecord:
    """Normalize a raw ``AgentInvocationResult`` into a durable persisted record."""
    import uuid

    status = _RESULT_TO_RECORD_STATUS.get(result.status, INVOCATION_STATUS_FAILED)
    response_text = result.response_text if status == INVOCATION_STATUS_RESPONSE_READY else None
    if status == INVOCATION_STATUS_RESPONSE_READY and not (response_text or "").strip():
        status = INVOCATION_STATUS_EMPTY_SUCCESS
        response_text = None
    return AgentInvocationRecord(
        invocation_id=invocation_id or f"invoke_{uuid.uuid4().hex[:12]}",
        instruction_id=instruction_id,
        backend_id=backend_id,
        session_id=session_id,
        turn_number=turn_number,
        status=status,
        response_text=response_text,
        response_sha256=_sha256_text(response_text) if response_text else None,
        stdout_summary=_summary(result.raw_stdout),
        stderr_summary=_summary(result.raw_stderr),
        exit_code=result.exit_code,
        error_message=result.error_message,
        started_at=result.started_at,
        completed_at=result.completed_at,
        prompt_mode=result.prompt_mode,
        instruction_file_path=result.instruction_file_path,
        instruction_sha256=result.instruction_sha256,
        adapter_prompt_length=result.adapter_prompt_length,
        adapter_line_count=result.adapter_line_count,
        adapter_contains_crlf=result.adapter_contains_crlf,
        adapter_sha256=result.adapter_sha256,
        full_instruction_length=result.full_instruction_length,
        stdout_length=result.stdout_length,
        invocation_duration_ms=result.invocation_duration_ms,
        environment_status=result.environment_status,
        environment_platform=result.environment_platform,
        environment_variable_names=result.environment_variable_names,
        unresolved_environment_variables=result.unresolved_environment_variables,
        cursor_profile_environment_present=result.cursor_profile_environment_present,
        program_data_path_present=result.program_data_path_present,
        environment_paths=result.environment_paths,
        attempt_number=attempt_number,
        retry_of_invocation_id=retry_of_invocation_id,
        estimated_cost=estimated_cost,
        operator_retry_count=operator_retry_count,
    )


@dataclass
class AgentBackendAvailability:
    """Display-only availability snapshot for a backend."""

    status: str
    configured: bool
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return self.status in (AGENT_AVAILABILITY_AVAILABLE, AGENT_AVAILABILITY_EXTERNAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "configured": self.configured,
            "available": self.available,
            "message": self.message,
            "detail": dict(self.detail),
        }


# ---------------------------------------------------------------------------
# Backend base class + concrete backends
# ---------------------------------------------------------------------------


class AgentBackend(ABC):
    """Common interface for a model-agnostic agent invocation backend."""

    backend_id: str = "backend"
    label: str = "Agent backend"

    @abstractmethod
    def availability(self) -> AgentBackendAvailability:
        """Report whether the backend is configured/available without invoking it."""

    @abstractmethod
    def invoke(self, request: AgentInvocationRequest) -> AgentInvocationResult:
        """Run one instruction turn and return a structured proposal-only result."""

    def status_snapshot(self) -> dict[str, Any]:
        """Display-only status for the UI. Never an authority source."""
        availability = self.availability()
        return {
            "backend_id": self.backend_id,
            "label": self.label,
            "callable": True,
            "availability": availability.to_dict(),
            "last_status": getattr(self, "_last_status", None),
        }

    def _record_status(self, status: str) -> None:
        self._last_status = status


class FixtureAgentBackend(AgentBackend):
    """Deterministic scripted backend for tests — no subprocess, no provider.

    ``invoke`` returns the next scripted response in order. Use ``malformed`` /
    ``unavailable`` sentinels (or call ``set_next_status``) to exercise the
    controller's bounded-retry and pause paths without a real agent.
    """

    backend_id = BACKEND_ID_FIXTURE
    label = "Fixture (test only)"

    def __init__(
        self,
        responses: list[str] | None = None,
        *,
        model_label: str = "fixture-model",
    ) -> None:
        self._responses: list[str] = list(responses or [])
        self._index = 0
        self._model_label = model_label
        self._forced_status: str | None = None
        self.invocations: list[AgentInvocationRequest] = []
        self._last_status: str | None = None

    def set_responses(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._index = 0

    def enqueue_response(self, text: str) -> None:
        self._responses.append(text)

    def set_next_status(self, status: str) -> None:
        """Force the *next* invoke to return ``status`` instead of a response."""
        self._forced_status = status

    def availability(self) -> AgentBackendAvailability:
        return AgentBackendAvailability(
            status=AGENT_AVAILABILITY_AVAILABLE,
            configured=True,
            message="Fixture backend returns scripted responses (test only).",
            detail={"scripted_responses": len(self._responses), "consumed": self._index},
        )

    def has_pending(self) -> bool:
        return self._index < len(self._responses)

    def invoke(self, request: AgentInvocationRequest) -> AgentInvocationResult:
        self.invocations.append(request)
        started = _now_iso()
        if self._forced_status is not None:
            forced = self._forced_status
            self._forced_status = None
            self._record_status(forced)
            return AgentInvocationResult(
                status=forced,
                model_label=self._model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=f"fixture forced status {forced!r}",
            )
        if self._index >= len(self._responses):
            self._record_status(AGENT_INVOKE_UNAVAILABLE)
            return AgentInvocationResult(
                status=AGENT_INVOKE_UNAVAILABLE,
                model_label=self._model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message="fixture backend has no more scripted responses",
            )
        text = self._responses[self._index]
        self._index += 1
        self._record_status(AGENT_INVOKE_SUCCESS)
        return AgentInvocationResult(
            status=AGENT_INVOKE_SUCCESS,
            response_text=text,
            raw_stdout=text,
            exit_code=0,
            model_label=self._model_label,
            transport_label=self.backend_id,
            started_at=started,
            completed_at=_now_iso(),
        )


class FileBridgeAgentBackend(AgentBackend):
    """Compatibility wrapper over the legacy Cursor GUI file bridge.

    Honestly reports that it is external/manual/semi-autonomous: ``invoke``
    writes the instruction and reads any response *already* present, but it
    never blocks for or drives an agent — a human still has to point Cursor at
    the bridge files. Kept so the existing FileBridge transport/tests are never
    removed or broken.
    """

    backend_id = BACKEND_ID_FILE_BRIDGE
    label = "Cursor GUI file bridge (external / semi-autonomous)"

    def __init__(self, workspace_path: str | Path) -> None:
        from admissible.agent_transport import FileBridgeAgentTransport

        self.workspace_path = str(workspace_path)
        self._transport = FileBridgeAgentTransport(workspace_path)
        self._last_status: str | None = None

    @property
    def transport(self) -> AgentTransport:
        return self._transport

    def availability(self) -> AgentBackendAvailability:
        return AgentBackendAvailability(
            status=AGENT_AVAILABILITY_EXTERNAL,
            configured=True,
            message=(
                "External/manual file bridge: a human must point Cursor (or another "
                "editor agent) at .admissible/next-agent-instruction.md and have it "
                "write .admissible/agent-response.md. Semi-autonomous only."
            ),
            detail={"workspace_path": self.workspace_path},
        )

    def invoke(self, request: AgentInvocationRequest) -> AgentInvocationResult:
        started = _now_iso()
        self._transport.write_instruction(
            request.instruction_text,
            turn_number=request.turn_number,
            session_id=request.session_id,
            instruction_id=request.instruction_id,
        )
        read = self._transport.read_response_if_changed()
        if read.changed and read.text:
            self._record_status(AGENT_INVOKE_SUCCESS)
            return AgentInvocationResult(
                status=AGENT_INVOKE_SUCCESS,
                response_text=read.text,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
            )
        self._record_status(AGENT_INVOKE_UNAVAILABLE)
        return AgentInvocationResult(
            status=AGENT_INVOKE_UNAVAILABLE,
            transport_label=self.backend_id,
            started_at=started,
            completed_at=_now_iso(),
            error_message=(
                "No response file yet. This backend is external/manual: waiting for a "
                "human-driven editor agent to write the response file."
            ),
        )


# ---------------------------------------------------------------------------
# Cursor CLI backend — model-agnostic pattern, Cursor first
# ---------------------------------------------------------------------------


def _parse_args_template(raw: str | None) -> list[str] | None:
    """Parse an argv template from JSON list or whitespace-split fallback.

    Returns ``None`` when nothing is configured; an empty list is treated as
    "configured but empty" by the caller (which then refuses to guess syntax).
    """
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        import json

        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
        return None
    return raw.split()


def _command_basename(command_path: str | None) -> str:
    return Path(command_path).name.lower() if command_path else ""


def is_cursor_agent_command(command_path: str | None) -> bool:
    """True when the command is the real Cursor Agent CLI (``cursor-agent``)."""
    return _command_basename(command_path) in _CURSOR_AGENT_COMMAND_NAMES


def _flag_value(tokens: list[str], flag: str) -> str | None:
    """Return the token following ``flag`` (or the ``flag=value`` tail)."""
    for index, token in enumerate(tokens):
        low = token.lower()
        if low == flag:
            return tokens[index + 1] if index + 1 < len(tokens) else None
        if low.startswith(flag + "="):
            return token.split("=", 1)[1]
    return None


def assess_cursor_cli_safety(
    command_path: str | None, args_template: list[str] | None
) -> tuple[list[str], list[str]]:
    """Return (blocking_reasons, warnings) for a Cursor CLI argv template.

    Admissible only runs the Cursor Agent CLI in read-only *planning* mode. This
    validation is defense-in-depth on top of the workspace separation and the
    ingest/admission path: it blocks configurations that would grant the agent
    unsupervised write/execute authority, and — for the ``cursor-agent`` command
    specifically — requires the read-only ``--print`` + plan-mode flags.
    """
    blocking: list[str] = []
    warnings: list[str] = []
    if not args_template:
        return blocking, warnings

    tokens = list(args_template)
    lower = [t.lower() for t in tokens]

    # Always-dangerous for any Cursor-family CLI, regardless of command name.
    for flag in _UNSAFE_CURSOR_FLAGS:
        if flag in lower:
            blocking.append(
                f"Unsafe flag {flag} is not allowed for the Cursor CLI backend "
                "(grants unsupervised write/execute authority)."
            )
    sandbox_value = _flag_value(tokens, "--sandbox")
    if (sandbox_value or "").lower() == "disabled":
        blocking.append("`--sandbox disabled` is not allowed; sandboxing must not be disabled.")

    # The IDE wrapper (`cursor agent ...`) does not expose the real Agent CLI.
    if _command_basename(command_path) in _CURSOR_IDE_COMMAND_NAMES and "agent" in lower:
        blocking.append(
            "Use the `cursor-agent` command, not `cursor agent`: the `cursor` IDE wrapper "
            "does not expose the real Cursor Agent CLI."
        )

    # A configured --workspace must always be the isolated agent workspace.
    if "--workspace" in lower:
        workspace_value = _flag_value(tokens, "--workspace") or ""
        if PLACEHOLDER_AGENT_WORKSPACE not in workspace_value:
            blocking.append(
                "--workspace must use the {agent_workspace} placeholder, never a fixed path "
                "or the target workspace."
            )

    # Cursor Agent read-only requirements only apply to the agent CLI itself.
    if is_cursor_agent_command(command_path):
        if "--print" not in lower:
            blocking.append("Cursor Agent CLI must run with --print (non-interactive).")
        mode_value = (_flag_value(tokens, "--mode") or "").lower()
        if mode_value != "plan" and "--plan" not in lower:
            blocking.append(
                "Cursor Agent CLI must run in read-only planning mode (--mode plan or --plan)."
            )
        output_value = (_flag_value(tokens, "--output-format") or "").lower()
        if output_value and output_value not in ("text", "json"):
            warnings.append(
                f"Cursor Agent --output-format {output_value!r} is not text/json; stdout may "
                "not ingest cleanly."
            )
        if "--model" not in lower:
            warnings.append("No --model configured; Cursor Agent will use its default model.")

    return blocking, warnings


def cursor_agent_cli_safe_args_template() -> list[str]:
    """The safe read-only Cursor Agent CLI argv template (as an argv list)."""
    return list(CURSOR_AGENT_CLI_SAFE_ARGS)


def cursor_agent_cli_preset_env(command: str = CURSOR_AGENT_CLI_COMMAND) -> dict[str, str]:
    """Environment variables that configure the safe Cursor Agent CLI preset."""
    return {
        CURSOR_CLI_COMMAND_ENV: command,
        CURSOR_CLI_ARGS_ENV: " ".join(CURSOR_AGENT_CLI_SAFE_ARGS),
        CURSOR_CLI_INPUT_MODE_ENV: INPUT_MODE_FILE_POINTER_ALWAYS,
        CURSOR_CLI_OUTPUT_MODE_ENV: OUTPUT_MODE_STDOUT,
        CURSOR_CLI_MODEL_LABEL_ENV: CURSOR_AGENT_CLI_MODEL_LABEL,
    }


@dataclass
class CursorCliConfig:
    """Safe, discovered/operator-supplied Cursor CLI configuration.

    Never hard-codes Cursor CLI syntax. ``command_path`` and ``args_template``
    come from the environment; without both a *usable* command and an argv
    template that shows how the instruction reaches the CLI, the config is not
    ``ready`` and the backend reports ``blocked_by_configuration`` instead of
    guessing.
    """

    command_path: str | None
    args_template: list[str] | None
    version_probe_args: list[str]
    input_mode: str
    output_mode: str
    model_label: str
    configured: bool

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "CursorCliConfig":
        env = dict(os.environ if env is None else env)
        command_path = (env.get(CURSOR_CLI_COMMAND_ENV) or "").strip() or None
        args_template = _parse_args_template(env.get(CURSOR_CLI_ARGS_ENV))
        version_args = _parse_args_template(env.get(CURSOR_CLI_VERSION_ARGS_ENV))
        if version_args is None:
            version_args = ["--version"]
        input_mode = (env.get(CURSOR_CLI_INPUT_MODE_ENV) or INPUT_MODE_INSTRUCTION_FILE).strip()
        if input_mode not in (
            INPUT_MODE_INSTRUCTION_FILE,
            INPUT_MODE_STDIN,
            INPUT_MODE_PROMPT_ARG,
            INPUT_MODE_FILE_POINTER_ALWAYS,
        ):
            input_mode = INPUT_MODE_INSTRUCTION_FILE
        output_mode = (env.get(CURSOR_CLI_OUTPUT_MODE_ENV) or OUTPUT_MODE_STDOUT).strip()
        if output_mode not in (OUTPUT_MODE_STDOUT, OUTPUT_MODE_RESPONSE_FILE):
            output_mode = OUTPUT_MODE_STDOUT
        # Cursor Agent's verified live contract is a single-line positional adapter
        # that points at the governed instruction file, with stdout as the only
        # response channel. Operator settings cannot downgrade this preset to a
        # raw positional prompt or response-file write.
        if is_cursor_agent_command(command_path):
            input_mode = INPUT_MODE_FILE_POINTER_ALWAYS
            output_mode = OUTPUT_MODE_STDOUT
        model_label = (env.get(CURSOR_CLI_MODEL_LABEL_ENV) or "cursor-cli").strip() or "cursor-cli"
        return cls(
            command_path=command_path,
            args_template=args_template,
            version_probe_args=version_args,
            input_mode=input_mode,
            output_mode=output_mode,
            model_label=model_label,
            configured=command_path is not None,
        )

    @classmethod
    def cursor_agent_preset(cls, command: str = CURSOR_AGENT_CLI_COMMAND) -> "CursorCliConfig":
        """Build the safe read-only Cursor Agent CLI preset config."""
        return cls.from_env(cursor_agent_cli_preset_env(command))

    @property
    def is_cursor_agent(self) -> bool:
        return is_cursor_agent_command(self.command_path)

    def uses_prompt_arg(self) -> bool:
        return self.input_mode in (INPUT_MODE_PROMPT_ARG, INPUT_MODE_FILE_POINTER_ALWAYS) or any(
            PLACEHOLDER_PROMPT in arg for arg in (self.args_template or [])
        )

    def safety_issues(self) -> tuple[list[str], list[str]]:
        return assess_cursor_cli_safety(self.command_path, self.args_template)

    def command_exists(self) -> bool:
        if not self.command_path:
            return False
        import shutil

        candidate = Path(self.command_path)
        if candidate.is_file():
            return True
        return shutil.which(self.command_path) is not None

    def resolved_command(self) -> str | None:
        if not self.command_path:
            return None
        candidate = Path(self.command_path)
        if candidate.is_file():
            return str(candidate)
        import shutil

        return shutil.which(self.command_path)

    def missing_reason(self) -> str | None:
        """Human/machine reason the config is not usable, or None when ready."""
        if not self.configured:
            return (
                f"Cursor CLI backend not configured. Set {CURSOR_CLI_COMMAND_ENV} to the "
                "Cursor CLI executable path and "
                f"{CURSOR_CLI_ARGS_ENV} to its argv template (must reference "
                f"{PLACEHOLDER_INSTRUCTION_FILE} for the instruction, unless input mode is stdin)."
            )
        if not self.command_exists():
            return f"Configured Cursor CLI command not found: {self.command_path!r}."
        if self.args_template is None:
            return (
                f"No Cursor CLI argv template configured. Set {CURSOR_CLI_ARGS_ENV} — this "
                "backend refuses to guess an unverified command syntax."
            )
        if not self.args_template:
            return (
                f"{CURSOR_CLI_ARGS_ENV} is empty. Provide the argv template that hands the "
                f"instruction to the CLI (e.g. reference {PLACEHOLDER_PROMPT} or "
                f"{PLACEHOLDER_INSTRUCTION_FILE})."
            )
        # The instruction must be able to reach the CLI: via a {prompt} argv
        # element, a {instruction_file} placeholder, or stdin input mode.
        has_prompt = any(PLACEHOLDER_PROMPT in arg for arg in self.args_template)
        has_instruction_file = any(
            PLACEHOLDER_INSTRUCTION_FILE in arg for arg in self.args_template
        )
        if self.is_cursor_agent and not has_prompt:
            return (
                "Cursor Agent CLI argv template must reference {prompt}; Admissible passes a "
                "short adapter prompt that points to the governed instruction file."
            )
        if not (has_prompt or has_instruction_file or self.input_mode == INPUT_MODE_STDIN):
            return (
                f"Cursor CLI argv template references neither {PLACEHOLDER_PROMPT} nor "
                f"{PLACEHOLDER_INSTRUCTION_FILE} (and input mode is not stdin); the instruction "
                "cannot be handed to the CLI safely."
            )
        blocking, _ = self.safety_issues()
        if blocking:
            return blocking[0]
        return None

    def ready(self) -> bool:
        return self.missing_reason() is None

    def display_label(self) -> str:
        return (
            "Cursor Agent CLI (plan mode, proposal-only)"
            if self.is_cursor_agent
            else "Cursor CLI / headless"
        )

    def safety_mode(self) -> str | None:
        """Short human-readable read-only safety mode string for the UI."""
        if not self.is_cursor_agent:
            return None
        return "Cursor Agent CLI · --print · --mode plan · isolated agent workspace · proposal-only"

    def to_dict(self) -> dict[str, Any]:
        blocking, warnings = self.safety_issues()
        return {
            "command_path": self.command_path,
            "resolved_command": self.resolved_command(),
            "args_template": list(self.args_template) if self.args_template is not None else None,
            "version_probe_args": list(self.version_probe_args),
            "input_mode": self.input_mode,
            "output_mode": self.output_mode,
            "model_label": self.model_label,
            "configured": self.configured,
            "command_exists": self.command_exists(),
            "ready": self.ready(),
            "missing_reason": self.missing_reason(),
            "is_cursor_agent": self.is_cursor_agent,
            "proposal_only": True,
            "display_label": self.display_label(),
            "safety_mode": self.safety_mode(),
            "safety_blocking": blocking,
            "safety_warnings": warnings,
        }


def _parent_env_lookup(source: dict[str, str], canonical_name: str) -> str | None:
    """Look up an environment value case-insensitively (Windows-safe)."""
    if canonical_name in source:
        return source[canonical_name]
    lower = canonical_name.lower()
    for key, value in source.items():
        if key.lower() == lower:
            return value
    return None


def _canonical_env_name(name: str) -> str:
    return _ENV_CANONICAL_BY_LOWER.get(name.lower(), name)


def _expand_percent_refs_once(value: str, resolved: dict[str, str]) -> str:
    """Expand ``%NAME%`` references using already-resolved env values (no shell)."""

    def repl(match: re.Match[str]) -> str:
        ref = match.group(1)
        canonical = _canonical_env_name(ref)
        return resolved.get(canonical, match.group(0))

    result = _WIN_PERCENT_REF.sub(repl, value)
    if len(result) > _MAX_ENV_VALUE_LEN:
        return value
    return result


def _unresolved_percent_refs(value: str) -> list[str]:
    return [_canonical_env_name(m.group(1)) for m in _WIN_PERCENT_REF.finditer(value)]


def _is_absolute_windows_path(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value.startswith("\\\\"):
        return True
    if len(value) >= 2 and value[1] == ":":
        return True
    if value.startswith("\\"):
        return True
    return False


def _is_drive_letter(value: str) -> bool:
    value = value.strip()
    return len(value) == 2 and value[1] == ":" and value[0].isalpha()


def _validate_path_like_env(name: str, value: str) -> bool:
    if name in _DRIVE_LETTER_VARS:
        return _is_drive_letter(value)
    if name == "HOMEPATH":
        return value.startswith("\\") or _is_absolute_windows_path(value)
    return _is_absolute_windows_path(value)


def _safe_environment_paths(resolved: dict[str, str]) -> dict[str, str]:
    """Expose known OS/profile path values for Advanced diagnostics (no secrets)."""
    expose = (
        "SystemDrive",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "TEMP",
        "TMP",
        "HOMEDRIVE",
        "HOMEPATH",
    )
    return {key: resolved[key] for key in expose if key in resolved}


def build_cursor_agent_safe_environment(
    base: dict[str, str] | None = None,
) -> tuple[dict[str, str] | None, dict[str, Any]]:
    """Build a Windows-aware safe subprocess environment for Cursor Agent.

    Preserves only the allowlisted OS/profile variables from the parent process,
    expands nested ``%NAME%`` references without invoking a shell, validates
    path-like values, and blocks when required values still contain unresolved
    tokens. Never forwards API keys, tokens, or unrelated application variables.
    """
    source = dict(os.environ if base is None else base)
    resolved: dict[str, str] = {}
    for canonical in _ENV_PRESERVE_CANONICAL:
        raw = _parent_env_lookup(source, canonical)
        if raw is not None:
            resolved[canonical] = raw

    for _ in range(_ENV_EXPANSION_MAX_ROUNDS):
        changed = False
        for key, value in list(resolved.items()):
            expanded = _expand_percent_refs_once(value, resolved)
            if expanded != value:
                resolved[key] = expanded
                changed = True
        if not changed:
            break

    unresolved: set[str] = set()
    path_validation_errors: list[str] = []
    for key, value in resolved.items():
        for ref in _unresolved_percent_refs(value):
            unresolved.add(ref)
        if key in _PATH_LIKE_ENV_VARS or key in _DRIVE_LETTER_VARS:
            if _unresolved_percent_refs(value):
                path_validation_errors.append(key)
            elif not _validate_path_like_env(key, value):
                path_validation_errors.append(key)

    program_data = resolved.get("ProgramData", "")
    diagnostics: dict[str, Any] = {
        "environment_status": "ok",
        "environment_platform": sys.platform,
        "environment_variable_names": sorted(resolved.keys()),
        "unresolved_environment_variables": sorted(unresolved),
        "cursor_profile_environment_present": (
            "APPDATA" in resolved and "LOCALAPPDATA" in resolved
        ),
        "program_data_path_present": bool(program_data)
        and not _WIN_PERCENT_REF.search(program_data),
        "environment_paths": _safe_environment_paths(resolved),
    }

    if unresolved or path_validation_errors:
        diagnostics["environment_status"] = "blocked"
        diagnostics["path_validation_errors"] = sorted(set(path_validation_errors))
        return None, diagnostics

    return resolved, diagnostics


def _sanitized_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Legacy entry point — delegates to ``build_cursor_agent_safe_environment``."""
    env, _diag = build_cursor_agent_safe_environment(base)
    if env is None:
        # Best-effort fallback for callers that ignore diagnostics; invoke() blocks properly.
        source = dict(os.environ if base is None else base)
        return {
            key: _parent_env_lookup(source, key)  # type: ignore[misc]
            for key in _ENV_PRESERVE_CANONICAL
            if _parent_env_lookup(source, key) is not None
        }
    return env


def probe_cursor_agent_cli_environment(
    config: "CursorCliConfig",
    *,
    agent_workspace_path: str | Path,
    env_base: dict[str, str] | None = None,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Probe ``cursor-agent --version`` with the same safe env/cwd as ``invoke``.

    Does not call a model. Intended for tests and operator diagnostics only.
    """
    availability_msg: str | None = None
    if not config.ready():
        availability_msg = config.missing_reason()
    command = config.resolved_command()
    env, env_diag = build_cursor_agent_safe_environment(env_base)
    agent_workspace = Path(str(agent_workspace_path)).resolve()
    result: dict[str, Any] = {
        "configured": config.configured,
        "ready": config.ready(),
        "missing_reason": availability_msg,
        "command": command,
        "agent_workspace_path": str(agent_workspace),
        **env_diag,
    }
    if availability_msg or not command:
        result["probe_status"] = "blocked_by_configuration"
        result["error_message"] = availability_msg or "Cursor CLI command not configured."
        return result
    if env is None:
        result["probe_status"] = "blocked_by_environment"
        result["error_message"] = (
            "Cursor Agent environment blocked: unresolved variables "
            f"{env_diag.get('unresolved_environment_variables')!r}."
        )
        return result

    argv = [command, *config.version_probe_args]
    run = runner if runner is not None else subprocess.run
    try:
        completed = run(
            argv,
            shell=False,
            cwd=str(agent_workspace),
            capture_output=True,
            text=True,
            timeout=30.0,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        result["probe_status"] = "timeout"
        result["error_message"] = str(exc)
        return result
    except (OSError, ValueError) as exc:
        result["probe_status"] = "failed"
        result["error_message"] = str(exc)
        return result

    stdout = (getattr(completed, "stdout", "") or "").strip()
    stderr = (getattr(completed, "stderr", "") or "").strip()
    exit_code = getattr(completed, "returncode", None)
    result.update(
        {
            "probe_status": "ok" if exit_code == 0 and stdout else "failed",
            "exit_code": exit_code,
            "stdout_length": len(stdout),
            "stderr_summary": _summary(stderr),
            "stdout_preview": stdout[:200] if stdout else None,
        }
    )
    if exit_code != 0:
        result["error_message"] = f"Version probe exited with code {exit_code}."
    elif not stdout:
        result["error_message"] = "Version probe produced empty stdout."
    return result


def _agent_bridge_dir(agent_workspace: Path) -> Path:
    return agent_workspace / AGENT_BRIDGE_SUBDIR


class CursorCliAgentBackend(AgentBackend):
    """Callable Cursor CLI / headless backend — disabled unless configured.

    Model-agnostic pattern with Cursor as the first concrete target. It never
    assumes an exact command syntax: the argv template is operator-supplied via
    the environment. When nothing safe is configured it returns
    ``blocked_by_configuration`` / ``unavailable`` with a clear message rather
    than guessing.

    Invocation always uses ``subprocess.run([...], shell=False, timeout=...,
    cwd=agent_workspace_path)`` with a size-capped output and a sanitized
    environment, and never runs in — nor is granted write authority over — the
    target workspace. Unit tests inject ``runner`` or mock ``subprocess.run``;
    a real Cursor CLI is never spawned in tests.
    """

    backend_id = BACKEND_ID_CURSOR_CLI
    label = "Cursor CLI / headless"

    def __init__(
        self,
        config: CursorCliConfig | None = None,
        *,
        runner: Callable[..., Any] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.config = config if config is not None else CursorCliConfig.from_env()
        # ``runner`` is resolved lazily to ``subprocess.run`` so tests that
        # patch ``subprocess.run`` take effect even when runner is left default.
        self._runner = runner
        self._env_base = env
        self._last_status: str | None = None
        self._last_result: AgentInvocationResult | None = None

    def _resolve_runner(self) -> Callable[..., Any]:
        return self._runner if self._runner is not None else subprocess.run

    def availability(self) -> AgentBackendAvailability:
        cfg = self.config
        if not cfg.configured:
            return AgentBackendAvailability(
                status=AGENT_AVAILABILITY_NOT_CONFIGURED,
                configured=False,
                message=cfg.missing_reason() or "Cursor CLI backend not configured.",
                detail=cfg.to_dict(),
            )
        if not cfg.command_exists():
            return AgentBackendAvailability(
                status=AGENT_AVAILABILITY_UNAVAILABLE,
                configured=True,
                message=cfg.missing_reason() or "Configured Cursor CLI command not found.",
                detail=cfg.to_dict(),
            )
        if not cfg.ready():
            return AgentBackendAvailability(
                status=AGENT_AVAILABILITY_UNSUPPORTED,
                configured=True,
                message=cfg.missing_reason() or "Cursor CLI configuration incomplete.",
                detail=cfg.to_dict(),
            )
        safety_mode = cfg.safety_mode()
        message = (
            f"{cfg.display_label()} configured and ready — {safety_mode}."
            if safety_mode
            else "Cursor CLI backend configured and ready."
        )
        return AgentBackendAvailability(
            status=AGENT_AVAILABILITY_AVAILABLE,
            configured=True,
            message=message,
            detail=cfg.to_dict(),
        )

    def _build_argv(
        self,
        request: AgentInvocationRequest,
        *,
        instruction_file: Path,
        response_file: Path,
        prompt_value: str,
    ) -> list[str]:
        command = self.config.resolved_command()
        assert command is not None  # guarded by availability() before invoke
        argv = [command]
        for token in self.config.args_template or []:
            token = token.replace(PLACEHOLDER_INSTRUCTION_FILE, str(instruction_file))
            token = token.replace(PLACEHOLDER_RESPONSE_FILE, str(response_file))
            token = token.replace(
                PLACEHOLDER_AGENT_WORKSPACE, str(request.agent_workspace_path or "")
            )
            # ``{prompt}`` is substituted with a single argv element (shell=False,
            # so it is never shell-interpreted or word-split).
            token = token.replace(PLACEHOLDER_PROMPT, prompt_value)
            argv.append(token)
        return argv

    def _prompt_value(
        self, request: AgentInvocationRequest, *, instruction_file: Path
    ) -> tuple[str, str]:
        """Return the ``{prompt}`` value and its diagnostic transport mode."""
        text = request.instruction_text
        if self.config.is_cursor_agent or self.config.input_mode == INPUT_MODE_FILE_POINTER_ALWAYS:
            if self.config.is_cursor_agent:
                adapter = build_cursor_agent_file_pointer_adapter(instruction_file)
            else:
                adapter = (
                    f"Read the instruction file at {instruction_file} and output only the Admissible "
                    "structured response. Do not modify any files; propose only."
                )
            return adapter, PROMPT_MODE_FILE_POINTER
        if len(text) <= PROMPT_ARG_MAX_CHARS:
            return text, PROMPT_MODE_INLINE
        adapter = (
            f"Read the instruction file at {instruction_file} and output only the Admissible "
            "structured response. Do not modify any files; propose only."
        )
        return adapter, PROMPT_MODE_FILE_POINTER

    def invoke(self, request: AgentInvocationRequest) -> AgentInvocationResult:
        started = _now_iso()
        started_clock = time.perf_counter()

        def duration_ms() -> float:
            return round((time.perf_counter() - started_clock) * 1000, 3)

        availability = self.availability()
        if availability.status != AGENT_AVAILABILITY_AVAILABLE:
            status = (
                AGENT_INVOKE_BLOCKED_BY_CONFIGURATION
                if availability.status
                in (AGENT_AVAILABILITY_NOT_CONFIGURED, AGENT_AVAILABILITY_UNSUPPORTED)
                else AGENT_INVOKE_UNAVAILABLE
            )
            self._last_status = status
            result = AgentInvocationResult(
                status=status,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=availability.message,
                full_instruction_length=len(request.instruction_text),
                invocation_duration_ms=duration_ms(),
            )
            self._last_result = result
            return result

        agent_workspace_raw = request.agent_workspace_path
        if not agent_workspace_raw:
            self._last_status = AGENT_INVOKE_BLOCKED_BY_CONFIGURATION
            result = AgentInvocationResult(
                status=AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message="No agent workspace configured for the Cursor CLI backend.",
                full_instruction_length=len(request.instruction_text),
                invocation_duration_ms=duration_ms(),
            )
            self._last_result = result
            return result

        agent_workspace = Path(agent_workspace_raw).resolve()
        # Guardrail: never run the agent in / against the target workspace.
        target = request.target_workspace_path
        if target and Path(target).resolve() == agent_workspace.resolve():
            self._last_status = AGENT_INVOKE_BLOCKED_BY_CONFIGURATION
            result = AgentInvocationResult(
                status=AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=(
                    "Agent workspace must differ from the target workspace; refusing to run "
                    "the agent with cwd inside the target workspace."
                ),
                full_instruction_length=len(request.instruction_text),
                invocation_duration_ms=duration_ms(),
            )
            self._last_result = result
            return result

        bridge_dir = _agent_bridge_dir(agent_workspace)
        bridge_dir.mkdir(parents=True, exist_ok=True)
        instruction_file = (bridge_dir / AGENT_INSTRUCTION_FILENAME).resolve()
        response_file = bridge_dir / AGENT_RESPONSE_FILENAME
        instruction_file.write_text(request.instruction_text, encoding="utf-8")
        # Clear any stale response before invoking so we never read an old turn.
        if self.config.output_mode == OUTPUT_MODE_RESPONSE_FILE and response_file.exists():
            response_file.unlink()

        prompt_value, prompt_mode = self._prompt_value(
            request, instruction_file=instruction_file
        )
        instruction_sha256 = _sha256_text(request.instruction_text)
        adapter_diag = (
            cursor_agent_adapter_diagnostics(prompt_value)
            if self.config.is_cursor_agent and prompt_mode == PROMPT_MODE_FILE_POINTER
            else {}
        )

        safe_env, env_diag = build_cursor_agent_safe_environment(self._env_base)
        env_fields = {
            "environment_status": env_diag.get("environment_status"),
            "environment_platform": env_diag.get("environment_platform"),
            "environment_variable_names": env_diag.get("environment_variable_names"),
            "unresolved_environment_variables": env_diag.get(
                "unresolved_environment_variables"
            ),
            "cursor_profile_environment_present": env_diag.get(
                "cursor_profile_environment_present"
            ),
            "program_data_path_present": env_diag.get("program_data_path_present"),
            "environment_paths": env_diag.get("environment_paths"),
        }

        def invocation_diagnostics(stdout: str = "", **extra: Any) -> dict[str, Any]:
            base = {
                "prompt_mode": prompt_mode,
                "instruction_file_path": str(instruction_file),
                "instruction_sha256": instruction_sha256,
                "adapter_prompt_length": (
                    adapter_diag.get("adapter_prompt_length")
                    if adapter_diag
                    else (len(prompt_value) if prompt_mode == PROMPT_MODE_FILE_POINTER else 0)
                ),
                "adapter_line_count": adapter_diag.get("adapter_line_count"),
                "adapter_contains_crlf": adapter_diag.get("adapter_contains_crlf"),
                "adapter_sha256": adapter_diag.get("adapter_sha256"),
                "full_instruction_length": len(request.instruction_text),
                "stdout_length": len(stdout),
                "invocation_duration_ms": duration_ms(),
            }
            base.update(env_fields)
            base.update(extra)
            return base

        if self.config.is_cursor_agent and prompt_mode == PROMPT_MODE_FILE_POINTER:
            adapter_error = validate_cursor_agent_file_pointer_adapter(prompt_value)
            if adapter_error:
                self._last_status = AGENT_INVOKE_BLOCKED_BY_CONFIGURATION
                result = AgentInvocationResult(
                    status=AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
                    model_label=self.config.model_label,
                    transport_label=self.backend_id,
                    started_at=started,
                    completed_at=_now_iso(),
                    error_message=adapter_error,
                    full_instruction_length=len(request.instruction_text),
                    invocation_duration_ms=duration_ms(),
                    **adapter_diag,
                    **env_fields,
                )
                self._last_result = result
                return result

        argv = self._build_argv(
            request,
            instruction_file=instruction_file,
            response_file=response_file,
            prompt_value=prompt_value,
        )
        stdin_text = (
            request.instruction_text if self.config.input_mode == INPUT_MODE_STDIN else None
        )
        if safe_env is None:
            unresolved = env_diag.get("unresolved_environment_variables") or []
            self._last_status = AGENT_INVOKE_BLOCKED_BY_CONFIGURATION
            result = AgentInvocationResult(
                status=AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=(
                    "Cursor Agent subprocess environment blocked: unresolved variables "
                    f"{unresolved!r}."
                ),
                full_instruction_length=len(request.instruction_text),
                invocation_duration_ms=duration_ms(),
                **env_fields,
            )
            self._last_result = result
            return result

        runner = self._resolve_runner()
        try:
            completed = runner(
                argv,
                shell=False,
                cwd=str(agent_workspace),
                timeout=request.timeout_seconds,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                input=stdin_text,
                env=safe_env,
            )
        except subprocess.TimeoutExpired as exc:
            self._last_status = AGENT_INVOKE_TIMEOUT
            result = AgentInvocationResult(
                status=AGENT_INVOKE_TIMEOUT,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=f"Cursor CLI timed out after {request.timeout_seconds}s: {exc}",
                **invocation_diagnostics(),
            )
            self._last_result = result
            return result
        except (OSError, ValueError) as exc:
            self._last_status = AGENT_INVOKE_FAILED
            result = AgentInvocationResult(
                status=AGENT_INVOKE_FAILED,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=f"Cursor CLI invocation failed: {exc}",
                **invocation_diagnostics(),
            )
            self._last_result = result
            return result

        stdout = _cap_text(getattr(completed, "stdout", "") or "", request.max_output_bytes)
        stderr = _cap_text(getattr(completed, "stderr", "") or "", request.max_output_bytes)
        exit_code = getattr(completed, "returncode", None)

        if self.config.output_mode == OUTPUT_MODE_RESPONSE_FILE:
            response_text = (
                _cap_text(response_file.read_text(encoding="utf-8"), request.max_output_bytes)
                if response_file.is_file()
                else ""
            )
        else:
            response_text = stdout

        if exit_code not in (0, None):
            self._last_status = AGENT_INVOKE_FAILED
            result = AgentInvocationResult(
                status=AGENT_INVOKE_FAILED,
                response_text=response_text or None,
                raw_stdout=stdout,
                raw_stderr=stderr,
                exit_code=exit_code,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=f"Cursor CLI exited with code {exit_code}.",
                **invocation_diagnostics(stdout),
            )
            self._last_result = result
            return result

        if not response_text.strip():
            stderr_is_nonfatal = not re.search(
                r"\b(error|fatal|traceback|exception)\b", stderr, re.IGNORECASE
            )
            empty_status = (
                AGENT_INVOKE_EMPTY_SUCCESS if stderr_is_nonfatal else AGENT_INVOKE_MALFORMED
            )
            self._last_status = empty_status
            result = AgentInvocationResult(
                status=empty_status,
                raw_stdout=stdout,
                raw_stderr=stderr,
                exit_code=exit_code,
                model_label=self.config.model_label,
                transport_label=self.backend_id,
                started_at=started,
                completed_at=_now_iso(),
                error_message=(
                    "Cursor CLI exited successfully but produced empty or whitespace-only stdout."
                    if empty_status == AGENT_INVOKE_EMPTY_SUCCESS
                    else "Cursor CLI produced no usable response text and stderr indicated a failure."
                ),
                **invocation_diagnostics(stdout),
            )
            self._last_result = result
            return result

        self._last_status = AGENT_INVOKE_SUCCESS
        result = AgentInvocationResult(
            status=AGENT_INVOKE_SUCCESS,
            response_text=response_text,
            raw_stdout=stdout,
            raw_stderr=stderr,
            exit_code=exit_code,
            model_label=self.config.model_label,
            transport_label=self.backend_id,
            started_at=started,
            completed_at=_now_iso(),
            **invocation_diagnostics(stdout),
        )
        self._last_result = result
        return result

    def status_snapshot(self) -> dict[str, Any]:
        base = super().status_snapshot()
        base["config"] = self.config.to_dict()
        if self._last_result is not None:
            base["last_result"] = self._last_result.to_dict()
        return base


def _cap_text(text: str, max_bytes: int) -> str:
    """Cap ``text`` to ``max_bytes`` UTF-8 bytes without splitting a codepoint."""
    if max_bytes is None or max_bytes <= 0:
        return text
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Callable-backend -> transport adapter
# ---------------------------------------------------------------------------


class CallableBackendTransport(AgentTransport):
    """Adapt a callable ``AgentBackend`` onto the tick-driven transport interface.

    The existing high-autonomy state machine writes an instruction, waits, then
    ingests a response file. This adapter reuses that machine for callable
    backends: ``write_instruction`` invokes the backend synchronously (one safe
    tick step, no hidden loop) and stashes the structured proposal;
    ``read_response_if_changed`` hands that stashed text back for ingest. The
    adapter itself never writes to the target workspace — the backend writes
    only inside the agent workspace, and admitted writes still flow solely
    through Admissible's bounded executor.
    """

    def __init__(
        self,
        backend: AgentBackend,
        *,
        target_workspace_path: str | Path,
        agent_workspace_path: str | Path,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.backend = backend
        self.target_workspace_path = str(target_workspace_path)
        self.agent_workspace_path = str(agent_workspace_path)
        self.max_output_bytes = max_output_bytes
        self.timeout_seconds = timeout_seconds
        self._pending_text: str | None = None
        self._pending_cursor: str | None = None
        self._last_cursor: str | None = None
        self._last_consumed_cursor: str | None = None
        self._current_turn: int | None = None
        self._session_id: str | None = None
        self._current_instruction_id: str | None = None
        self._last_result: AgentInvocationResult | None = None
        self._status_code = TRANSPORT_STATUS_IDLE
        self._status_detail: dict[str, Any] = {}

    @property
    def backend_id(self) -> str:
        return getattr(self.backend, "backend_id", "backend")

    @property
    def last_invocation_result(self) -> AgentInvocationResult | None:
        return self._last_result

    def write_instruction(
        self,
        text: str,
        *,
        turn_number: int | None = None,
        session_id: str | None = None,
        instruction_id: str | None = None,
    ) -> dict[str, Any]:
        self._current_turn = turn_number
        self._session_id = session_id
        self._current_instruction_id = instruction_id
        request = AgentInvocationRequest(
            instruction_text=text,
            session_id=session_id,
            turn_number=turn_number,
            instruction_id=instruction_id,
            target_workspace_path=self.target_workspace_path,
            agent_workspace_path=self.agent_workspace_path,
            max_output_bytes=self.max_output_bytes,
            timeout_seconds=self.timeout_seconds,
        )
        result = self.backend.invoke(request)
        self._last_result = result
        if result.ok and result.response_text is not None:
            self._pending_text = result.response_text
            self._pending_cursor = _sha256_text(result.response_text)
            self.note_status(
                TRANSPORT_STATUS_INSTRUCTION_WRITTEN,
                turn=turn_number,
                backend=self.backend_id,
                invoke_status=result.status,
            )
        else:
            self._pending_text = None
            self._pending_cursor = None
            self.note_status(
                TRANSPORT_STATUS_ERROR,
                turn=turn_number,
                backend=self.backend_id,
                invoke_status=result.status,
                error=result.error_message,
            )
        return {
            "transport": "callable_backend",
            "backend_id": self.backend_id,
            "turn": turn_number,
            "session_id": session_id,
            "instruction_id": instruction_id,
            "invoke_status": result.status,
            "invoke_result": result.to_dict(),
            "agent_workspace_path": self.agent_workspace_path,
            "target_workspace_path": self.target_workspace_path,
        }

    def read_response_if_changed(self) -> AgentTransportReadResult:
        if self._pending_text is None:
            self.note_status(
                TRANSPORT_STATUS_WAITING,
                backend=self.backend_id,
                invoke_status=(self._last_result.status if self._last_result else None),
            )
            return AgentTransportReadResult(
                changed=False,
                text=None,
                cursor=self._last_cursor,
                metadata={
                    "backend_id": self.backend_id,
                    "invoke_status": (self._last_result.status if self._last_result else None),
                },
                status=TRANSPORT_STATUS_WAITING,
            )
        text = self._pending_text
        cursor = self._pending_cursor or _sha256_text(text)
        self._pending_text = None
        self._pending_cursor = None
        self._last_cursor = cursor
        self.note_status(TRANSPORT_STATUS_RESPONSE_DETECTED, cursor=cursor, backend=self.backend_id)
        return AgentTransportReadResult(
            changed=True,
            text=text,
            cursor=cursor,
            metadata={"backend_id": self.backend_id},
            status=TRANSPORT_STATUS_RESPONSE_DETECTED,
        )

    @property
    def response_cursor(self) -> str | None:
        return self._last_cursor

    def clear_or_archive_response(self) -> dict[str, Any] | None:
        self._pending_text = None
        self._pending_cursor = None
        return {"cleared": True}

    def mark_response_consumed(self, *, turn_number: int, response_sha256: str) -> None:
        self._last_consumed_cursor = response_sha256 or self._last_cursor
        self.note_status(
            TRANSPORT_STATUS_RESPONSE_CONSUMED, turn=turn_number, backend=self.backend_id
        )

    def mark_response_ingested(self, *, turn_number: int, response_sha256: str) -> None:
        self.mark_response_consumed(turn_number=turn_number, response_sha256=response_sha256)

    def has_pending_response(self) -> bool:
        return self._pending_text is not None

    def status_snapshot(self) -> dict[str, Any]:
        base = super().status_snapshot()
        base.update(
            {
                "transport_kind": "callable_backend",
                "backend_id": self.backend_id,
                "workspace_path": self.target_workspace_path,
                "target_workspace_path": self.target_workspace_path,
                "agent_workspace_path": self.agent_workspace_path,
                "current_turn": self._current_turn,
                "session_id": self._session_id,
                "instruction_id": self._current_instruction_id,
                "last_response_cursor": self._last_cursor,
                "last_consumed_cursor": self._last_consumed_cursor,
                "last_invoke_status": (self._last_result.status if self._last_result else None),
                "last_invoke_error": (
                    self._last_result.error_message if self._last_result else None
                ),
            }
        )
        return base


# ---------------------------------------------------------------------------
# Target / agent workspace separation + safety
# ---------------------------------------------------------------------------

DEFAULT_AGENT_WORKSPACE_SUBDIR = (".admissible", "agent_workspace")


def default_agent_workspace_path(target_workspace_path: str | Path) -> Path:
    """Return the default isolated agent workspace under the target workspace.

    ``<target>/.admissible/agent_workspace`` — inside the target tree but never
    an application-file location: only bridge instruction/response files live
    here, and the bounded executor never treats it as an admitted write target.
    """
    target = Path(str(target_workspace_path))
    return target.joinpath(*DEFAULT_AGENT_WORKSPACE_SUBDIR)


def ensure_agent_workspace(target_workspace_path: str | Path) -> Path:
    agent_ws = default_agent_workspace_path(target_workspace_path)
    agent_ws.mkdir(parents=True, exist_ok=True)
    return agent_ws


# Marker files/dirs that strongly suggest a path is the agent-os repo itself.
_AGENT_OS_REPO_MARKERS = ("admissible", "benchmark", "tests")


def looks_like_agent_os_repo(path: str | Path, repo_root: str | Path | None = None) -> bool:
    """Heuristic: does ``path`` look like the agent-os repo (never a safe target)?

    True when the path *is* the configured repo root, or contains the tell-tale
    ``admissible/`` + ``benchmark/`` + ``tests/`` layout of this repository.
    """
    try:
        candidate = Path(str(path)).resolve()
    except (OSError, ValueError):
        return False
    if repo_root is not None:
        try:
            if candidate == Path(str(repo_root)).resolve():
                return True
        except (OSError, ValueError):
            pass
    if not candidate.is_dir():
        return False
    return all((candidate / marker).is_dir() for marker in _AGENT_OS_REPO_MARKERS)


@dataclass
class WorkspaceSafetyAssessment:
    """Display/control-only safety verdict for target + agent workspace pairing."""

    target_workspace_path: str | None
    agent_workspace_path: str | None
    target_exists: bool
    target_is_agent_os_repo: bool
    agent_equals_target: bool
    high_autonomy: bool
    allow_repo_target: bool
    blocking_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def safe_to_start(self) -> bool:
        return not self.blocking_reasons

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_workspace_path": self.target_workspace_path,
            "agent_workspace_path": self.agent_workspace_path,
            "target_exists": self.target_exists,
            "target_is_agent_os_repo": self.target_is_agent_os_repo,
            "agent_equals_target": self.agent_equals_target,
            "high_autonomy": self.high_autonomy,
            "allow_repo_target": self.allow_repo_target,
            "blocking_reasons": list(self.blocking_reasons),
            "warnings": list(self.warnings),
            "safe_to_start": self.safe_to_start,
        }


def assess_workspace_safety(
    *,
    target_workspace_path: str | Path | None,
    agent_workspace_path: str | Path | None = None,
    repo_root: str | Path | None = None,
    high_autonomy: bool = False,
    allow_repo_target: bool = False,
) -> WorkspaceSafetyAssessment:
    """Assess whether a target/agent workspace pairing is safe to start a run.

    Blocking (cannot start): no target workspace; target does not exist; target
    looks like the agent-os repo (unless explicitly allowed); agent workspace
    equals target workspace in high-autonomy mode. Warnings (start allowed but
    surfaced): agent workspace equals target outside high-autonomy mode.
    """
    target_raw = str(target_workspace_path).strip() if target_workspace_path else ""
    blocking: list[str] = []
    warnings: list[str] = []

    if not target_raw:
        return WorkspaceSafetyAssessment(
            target_workspace_path=None,
            agent_workspace_path=(str(agent_workspace_path) if agent_workspace_path else None),
            target_exists=False,
            target_is_agent_os_repo=False,
            agent_equals_target=False,
            high_autonomy=high_autonomy,
            allow_repo_target=allow_repo_target,
            blocking_reasons=["No target workspace configured."],
            warnings=warnings,
        )

    target = Path(target_raw)
    target_exists = target.is_dir()
    if not target_exists:
        blocking.append(f"Target workspace does not exist or is not a directory: {target_raw}")

    is_repo = looks_like_agent_os_repo(target, repo_root=repo_root)
    if is_repo and not allow_repo_target:
        blocking.append(
            "Target workspace looks like the agent-os repository; refusing to run against it. "
            "Choose a separate project workspace, or explicitly allow it."
        )

    agent_ws = (
        Path(str(agent_workspace_path))
        if agent_workspace_path
        else default_agent_workspace_path(target)
    )
    try:
        agent_equals_target = agent_ws.resolve() == target.resolve()
    except (OSError, ValueError):
        agent_equals_target = str(agent_ws) == str(target)
    if agent_equals_target:
        if high_autonomy:
            blocking.append(
                "Agent workspace must not be the same path as the target workspace in "
                "high-autonomy mode."
            )
        else:
            warnings.append(
                "Agent workspace is the same path as the target workspace; the agent should "
                "use an isolated workspace so it cannot see or touch application files directly."
            )

    return WorkspaceSafetyAssessment(
        target_workspace_path=str(target),
        agent_workspace_path=str(agent_ws),
        target_exists=target_exists,
        target_is_agent_os_repo=is_repo,
        agent_equals_target=agent_equals_target,
        high_autonomy=high_autonomy,
        allow_repo_target=allow_repo_target,
        blocking_reasons=blocking,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Backend registry (display-only) for the Control Surface
# ---------------------------------------------------------------------------


def describe_available_backends(env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Display-only list of selectable agent backends and their availability.

    Pure discovery: constructs each backend's availability snapshot without
    invoking anything or calling a provider. The fixture backend is marked
    test-only.
    """
    cursor_config = CursorCliConfig.from_env(env)
    cursor = CursorCliAgentBackend(config=cursor_config)
    cursor_availability = cursor.availability()
    return [
        {
            "backend_id": BACKEND_ID_FILE_BRIDGE,
            "label": FileBridgeAgentBackend.label,
            "callable": False,
            "semi_autonomous": True,
            "availability": {
                "status": AGENT_AVAILABILITY_EXTERNAL,
                "configured": True,
                "available": True,
                "message": (
                    "External/manual Cursor GUI file bridge. Semi-autonomous: a human keeps "
                    "the editor agent pointed at the bridge files."
                ),
                "detail": {},
            },
        },
        {
            "backend_id": BACKEND_ID_CURSOR_CLI,
            "label": cursor_config.display_label(),
            "callable": True,
            "semi_autonomous": False,
            "proposal_only": True,
            "safety_mode": cursor_config.safety_mode(),
            "is_cursor_agent": cursor_config.is_cursor_agent,
            "availability": cursor_availability.to_dict(),
        },
        {
            "backend_id": BACKEND_ID_FIXTURE,
            "label": FixtureAgentBackend.label,
            "callable": True,
            "semi_autonomous": False,
            "test_only": True,
            "availability": {
                "status": AGENT_AVAILABILITY_AVAILABLE,
                "configured": True,
                "available": True,
                "message": "Deterministic scripted backend for tests only.",
                "detail": {},
            },
        },
    ]


__all__ = [
    "AGENT_INVOKE_SUCCESS",
    "AGENT_INVOKE_UNAVAILABLE",
    "AGENT_INVOKE_TIMEOUT",
    "AGENT_INVOKE_FAILED",
    "AGENT_INVOKE_MALFORMED",
    "AGENT_INVOKE_EMPTY_SUCCESS",
    "AGENT_INVOKE_BLOCKED_BY_CONFIGURATION",
    "AGENT_INVOKE_STATUS_CODES",
    "AGENT_INVOKE_TERMINAL_STATUSES",
    "AGENT_AVAILABILITY_AVAILABLE",
    "AGENT_AVAILABILITY_NOT_CONFIGURED",
    "AGENT_AVAILABILITY_UNAVAILABLE",
    "AGENT_AVAILABILITY_UNSUPPORTED",
    "AGENT_AVAILABILITY_EXTERNAL",
    "BACKEND_ID_FIXTURE",
    "BACKEND_ID_FILE_BRIDGE",
    "BACKEND_ID_CURSOR_CLI",
    "CURSOR_CLI_COMMAND_ENV",
    "CURSOR_CLI_ARGS_ENV",
    "CURSOR_CLI_VERSION_ARGS_ENV",
    "CURSOR_CLI_INPUT_MODE_ENV",
    "CURSOR_CLI_OUTPUT_MODE_ENV",
    "CURSOR_CLI_MODEL_LABEL_ENV",
    "CURSOR_AGENT_CLI_COMMAND",
    "CURSOR_AGENT_CLI_SAFE_ARGS",
    "CURSOR_AGENT_CLI_MODEL_LABEL",
    "INPUT_MODE_FILE_POINTER_ALWAYS",
    "INPUT_MODE_PROMPT_ARG",
    "PROMPT_MODE_FILE_POINTER",
    "PROMPT_MODE_INLINE",
    "PLACEHOLDER_PROMPT",
    "PROMPT_ARG_MAX_CHARS",
    "assess_cursor_cli_safety",
    "cursor_agent_cli_safe_args_template",
    "cursor_agent_cli_preset_env",
    "is_cursor_agent_command",
    "INVOCATION_STATUS_INVOKING",
    "INVOCATION_STATUS_RESPONSE_READY",
    "INVOCATION_STATUS_CONSUMED",
    "INVOCATION_STATUS_TIMEOUT",
    "INVOCATION_STATUS_FAILED",
    "INVOCATION_STATUS_MALFORMED",
    "INVOCATION_STATUS_EMPTY_SUCCESS",
    "CALLABLE_STEP_INVOKING",
    "CALLABLE_STEP_RESPONSE_READY",
    "CALLABLE_STEP_INGESTING",
    "CALLABLE_STEP_CONSUMED",
    "AgentInvocationRequest",
    "AgentInvocationResult",
    "AgentInvocationRecord",
    "build_invocation_record",
    "AgentBackendAvailability",
    "AgentBackend",
    "FixtureAgentBackend",
    "FileBridgeAgentBackend",
    "CursorCliAgentBackend",
    "CursorCliConfig",
    "CallableBackendTransport",
    "WorkspaceSafetyAssessment",
    "assess_workspace_safety",
    "default_agent_workspace_path",
    "ensure_agent_workspace",
    "looks_like_agent_os_repo",
    "describe_available_backends",
    "build_cursor_agent_file_pointer_adapter",
    "validate_cursor_agent_file_pointer_adapter",
    "cursor_agent_adapter_diagnostics",
    "build_cursor_agent_safe_environment",
    "probe_cursor_agent_cli_environment",
    "_sanitized_env",
]
