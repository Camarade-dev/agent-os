"""Isolated diagnostic harness for the Cursor CLI callable-backend transport.

Slice ``ADMISSIBLE_RUN_046_CALLABLE_BACKEND_TRANSPORT_FORENSICS_AND_PROTOCOL_DECISION``.

Purpose: distinguish CLI/service failure from adapter/process-capture defects
by observing the same subprocess boundary two ways -- a *direct* Cursor CLI
invocation built independently of ``admissible.agent_backend``, and an
*adapter* invocation that drives the real ``CursorCliAgentBackend`` with an
injected low-level runner so its production argv/env/validation logic runs
unmodified while the harness still observes incremental stdout/stderr timing
and the full OS process tree.

Empirically verified precondition motivating the process-tree work below:
on Windows, ``cursor-agent`` resolves through a ``.CMD`` wrapper that spawns
``powershell.exe``, which spawns ``node.exe`` (the process actually holding
the model connection). ``subprocess.run(..., timeout=...)``'s own cleanup on
``TimeoutExpired`` only terminates the *direct* child (the ``.CMD``'s
``cmd.exe`` host) -- ``powershell.exe`` and ``node.exe`` are left running,
orphaned. This harness always attempts a recursive tree-kill instead.

Hard constraints (ADMISSIBLE_RUN_046):

- Serial execution only; no concurrency, no automatic retry. Each ``run_*``
  call is exactly one attempt; retrying is an explicit, separate call the
  operator/caller makes on purpose.
- A hard real-invocation budget (default 6) shared across ``run_direct_probe``
  and ``run_adapter_probe`` for one harness instance; exceeding it raises
  ``InvocationBudgetExceeded`` rather than silently proceeding.
  ``run_acp_handshake_probe`` never sends a prompt and does not consume it.
- Every probe gets its own isolated temporary workspace under the system
  temp directory (or an explicit ``workspace_root``); never an application
  workspace, never this repository.
- Only bounded, redacted diagnostic data is retained in a written report:
  stdout/stderr previews are truncated, environment values are never
  captured (only variable names, via ``build_cursor_agent_safe_environment``'s
  existing redaction), and process-tree evidence records only pids/names.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from admissible.agent_backend import (
    CURSOR_AGENT_CLI_COMMAND,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    build_cursor_agent_file_pointer_adapter,
    build_cursor_agent_safe_environment,
    cursor_agent_cli_safe_args_template,
    is_cursor_agent_command,
    validate_cursor_agent_file_pointer_adapter,
)

try:
    import psutil
except ImportError:  # pragma: no cover - environment without psutil installed
    psutil = None  # type: ignore[assignment]


# -- classification vocabulary (PART C.8) ------------------------------------
PROBE_STATUS_SUCCESS = "success"
PROBE_STATUS_EMPTY_SUCCESS = "empty_success"
PROBE_STATUS_TIMEOUT_BEFORE_ANY_OUTPUT = "timeout_before_any_output"
PROBE_STATUS_TIMEOUT_AFTER_PARTIAL_OUTPUT = "timeout_after_partial_output"
PROBE_STATUS_NONZERO_EXIT = "nonzero_exit"
PROBE_STATUS_WRAPPER_FAILURE = "wrapper_failure"
PROBE_STATUS_PARSE_FAILURE = "parse_failure"

PROBE_STATUS_CODES = frozenset(
    {
        PROBE_STATUS_SUCCESS,
        PROBE_STATUS_EMPTY_SUCCESS,
        PROBE_STATUS_TIMEOUT_BEFORE_ANY_OUTPUT,
        PROBE_STATUS_TIMEOUT_AFTER_PARTIAL_OUTPUT,
        PROBE_STATUS_NONZERO_EXIT,
        PROBE_STATUS_WRAPPER_FAILURE,
        PROBE_STATUS_PARSE_FAILURE,
    }
)

PROBE_PATH_DIRECT = "direct"
PROBE_PATH_ADAPTER = "adapter"

_PREVIEW_MAX_CHARS = 400
_MAX_CAPTURE_BYTES = 256 * 1024
DEFAULT_MAX_REAL_INVOCATIONS = 6
DEFAULT_PROBE_TIMEOUT_SECONDS = 120.0
_TREE_KILL_GRACE_SECONDS = 5.0


class InvocationBudgetExceeded(RuntimeError):
    """Raised when a probe would exceed the hard real-invocation budget."""


class ProbeAlreadyRunning(RuntimeError):
    """Raised on any attempted concurrent/re-entrant probe (serial-only)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _redact_preview(text: str | None, max_chars: int = _PREVIEW_MAX_CHARS) -> str | None:
    if text is None:
        return None
    text = text.strip("﻿")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"…[+{len(text) - max_chars} chars truncated]"


def _cap_text(text: str, max_bytes: int = _MAX_CAPTURE_BYTES) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Process-tree observation (PART C.7)
# ---------------------------------------------------------------------------


@dataclass
class ProcessTreeSnapshot:
    """Bounded, redacted process-tree evidence -- pids/names only, no cmdlines."""

    observed_via: str  # "psutil" | "unavailable"
    root_pid: int | None
    descendants: list[dict[str, Any]] = field(default_factory=list)
    all_terminated: bool | None = None
    survivors_after_cleanup: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_via": self.observed_via,
            "root_pid": self.root_pid,
            "descendant_count": len(self.descendants),
            "descendants": list(self.descendants),
            "all_terminated": self.all_terminated,
            "survivor_count": len(self.survivors_after_cleanup),
            "survivors_after_cleanup": list(self.survivors_after_cleanup),
        }


def _snapshot_tree(root_pid: int) -> tuple[str, list[Any]]:
    """Return (observed_via, list-of-psutil.Process) for root_pid + descendants."""
    if psutil is None:
        return "unavailable", []
    try:
        root = psutil.Process(root_pid)
    except psutil.NoSuchProcess:
        return "psutil", []
    try:
        descendants = root.children(recursive=True)
    except psutil.Error:
        descendants = []
    return "psutil", [root, *descendants]


def _describe(proc: Any) -> dict[str, Any]:
    try:
        return {"pid": proc.pid, "name": proc.name(), "status": proc.status()}
    except Exception:  # pragma: no cover - process already gone
        return {"pid": getattr(proc, "pid", None), "name": None, "status": "gone"}


def tree_kill(root_pid: int, *, grace_seconds: float = _TREE_KILL_GRACE_SECONDS) -> ProcessTreeSnapshot:
    """Recursively terminate ``root_pid`` and all descendants; report survivors.

    Plain ``Popen.kill()``/``subprocess.run(timeout=...)`` only terminates the
    direct child. On Windows, ``cursor-agent`` resolves through a ``.CMD`` ->
    ``powershell.exe`` -> ``node.exe`` chain; killing only the direct child
    leaves the last two processes running, orphaned, still holding the model
    connection. This always walks and kills the full tree instead.
    """
    observed_via, procs = _snapshot_tree(root_pid)
    if not procs:
        return ProcessTreeSnapshot(observed_via=observed_via, root_pid=root_pid, all_terminated=None)

    before = [_describe(p) for p in procs]
    for proc in reversed(procs):  # descendants first, root last
        try:
            proc.kill()
        except Exception:
            pass
    survivors: list[Any] = []
    try:
        _gone, survivors = psutil.wait_procs(procs, timeout=grace_seconds)
    except Exception:
        pass
    survivor_descriptions = [_describe(p) for p in survivors]
    return ProcessTreeSnapshot(
        observed_via=observed_via,
        root_pid=root_pid,
        descendants=before,
        all_terminated=not survivor_descriptions,
        survivors_after_cleanup=survivor_descriptions,
    )


# ---------------------------------------------------------------------------
# Low-level incremental-capture subprocess runner
# ---------------------------------------------------------------------------


@dataclass
class SubprocessCaptureResult:
    """Raw, unredacted capture of one subprocess invocation (in-memory only)."""

    argv_length: int
    process_started: bool = False
    process_started_at: str | None = None
    pid: int | None = None
    first_stdout_byte_at: str | None = None
    first_stdout_byte_elapsed_ms: float | None = None
    first_stderr_byte_at: str | None = None
    first_stderr_byte_elapsed_ms: float | None = None
    process_exit_code: int | None = None
    process_exit_at: str | None = None
    total_duration_ms: float | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    wrapper_error: str | None = None
    process_tree: ProcessTreeSnapshot | None = None

    @property
    def cancellation_cleanup_failure(self) -> bool:
        return bool(self.process_tree and self.process_tree.all_terminated is False)


def _run_with_incremental_capture(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout_seconds: float,
    input_text: str | None = None,
) -> SubprocessCaptureResult:
    """Spawn ``argv``, observing first-byte timing, with a guaranteed tree-kill.

    Never retries. Always attempts process-tree cleanup on timeout, whether or
    not the wait itself succeeds.
    """
    result = SubprocessCaptureResult(argv_length=len(argv))
    started_clock = time.perf_counter()

    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, ValueError) as exc:
        result.wrapper_error = f"{type(exc).__name__}: {exc}"
        return result

    result.process_started = True
    result.process_started_at = _now_iso()
    result.pid = proc.pid

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    first_stdout_event = threading.Event()
    first_stderr_event = threading.Event()

    def _reader(stream: Any, chunks: list[str], first_event: threading.Event, mark: Callable[[], None]) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not chunks and not first_event.is_set():
                    mark()
                    first_event.set()
                chunks.append(line)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _mark_stdout() -> None:
        result.first_stdout_byte_at = _now_iso()
        result.first_stdout_byte_elapsed_ms = round((time.perf_counter() - started_clock) * 1000, 3)

    def _mark_stderr() -> None:
        result.first_stderr_byte_at = _now_iso()
        result.first_stderr_byte_elapsed_ms = round((time.perf_counter() - started_clock) * 1000, 3)

    stdout_thread = threading.Thread(
        target=_reader, args=(proc.stdout, stdout_chunks, first_stdout_event, _mark_stdout), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_reader, args=(proc.stderr, stderr_chunks, first_stderr_event, _mark_stderr), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    if input_text is not None and proc.stdin is not None:
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except Exception:
            pass

    try:
        proc.wait(timeout=timeout_seconds)
        result.timed_out = False
    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.process_tree = tree_kill(proc.pid)
        try:
            proc.wait(timeout=_TREE_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass

    stdout_thread.join(timeout=5.0)
    stderr_thread.join(timeout=5.0)

    result.process_exit_code = proc.poll()
    result.process_exit_at = _now_iso()
    result.total_duration_ms = round((time.perf_counter() - started_clock) * 1000, 3)
    result.stdout = _cap_text("".join(stdout_chunks))
    result.stderr = _cap_text("".join(stderr_chunks))
    return result


def _classify(capture: SubprocessCaptureResult, response_text: str | None) -> str:
    if capture.wrapper_error:
        return PROBE_STATUS_WRAPPER_FAILURE
    if capture.timed_out:
        has_output = bool((capture.stdout or "").strip() or (capture.stderr or "").strip())
        return PROBE_STATUS_TIMEOUT_AFTER_PARTIAL_OUTPUT if has_output else PROBE_STATUS_TIMEOUT_BEFORE_ANY_OUTPUT
    if capture.process_exit_code not in (0, None):
        return PROBE_STATUS_NONZERO_EXIT
    if not (response_text or "").strip():
        return PROBE_STATUS_EMPTY_SUCCESS
    return PROBE_STATUS_SUCCESS


# ---------------------------------------------------------------------------
# Per-invocation report
# ---------------------------------------------------------------------------


@dataclass
class ProbeInvocationReport:
    probe_id: str
    label: str
    path: str  # PROBE_PATH_DIRECT | PROBE_PATH_ADAPTER
    attempt_number: int
    retry_of_probe_id: str | None
    instruction_sha256: str
    instruction_byte_length: int
    command: str | None
    model_label: str | None
    timeout_seconds: float
    process_started: bool
    process_started_at: str | None
    pid: int | None
    first_stdout_byte_at: str | None
    first_stdout_byte_elapsed_ms: float | None
    first_stderr_byte_at: str | None
    first_stderr_byte_elapsed_ms: float | None
    process_exit_code: int | None
    process_exit_at: str | None
    total_duration_ms: float | None
    timed_out: bool
    stdout_byte_count: int
    stderr_byte_count: int
    stdout_preview: str | None
    stderr_preview: str | None
    response_sha256: str | None
    usable_response_detected: bool
    classification: str
    error_message: str | None
    process_tree: dict[str, Any] | None
    cancellation_cleanup_failure: bool
    adapter_invoke_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "label": self.label,
            "path": self.path,
            "attempt_number": self.attempt_number,
            "retry_of_probe_id": self.retry_of_probe_id,
            "instruction_sha256": self.instruction_sha256,
            "instruction_byte_length": self.instruction_byte_length,
            "command": self.command,
            "model_label": self.model_label,
            "timeout_seconds": self.timeout_seconds,
            "process_started": self.process_started,
            "process_started_at": self.process_started_at,
            "pid": self.pid,
            "first_stdout_byte_at": self.first_stdout_byte_at,
            "first_stdout_byte_elapsed_ms": self.first_stdout_byte_elapsed_ms,
            "first_stderr_byte_at": self.first_stderr_byte_at,
            "first_stderr_byte_elapsed_ms": self.first_stderr_byte_elapsed_ms,
            "process_exit_code": self.process_exit_code,
            "process_exit_at": self.process_exit_at,
            "total_duration_ms": self.total_duration_ms,
            "timed_out": self.timed_out,
            "stdout_byte_count": self.stdout_byte_count,
            "stderr_byte_count": self.stderr_byte_count,
            "stdout_preview": self.stdout_preview,
            "stderr_preview": self.stderr_preview,
            "response_sha256": self.response_sha256,
            "usable_response_detected": self.usable_response_detected,
            "classification": self.classification,
            "error_message": self.error_message,
            "process_tree": self.process_tree,
            "cancellation_cleanup_failure": self.cancellation_cleanup_failure,
            "adapter_invoke_status": self.adapter_invoke_status,
        }


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class CallableBackendProbeHarness:
    """Serial, budget-bounded diagnostic harness. Never used by production code."""

    def __init__(
        self,
        *,
        max_real_invocations: int = DEFAULT_MAX_REAL_INVOCATIONS,
        workspace_root: str | Path | None = None,
    ) -> None:
        self.max_real_invocations = max_real_invocations
        self.used_real_invocations = 0
        self.probe_log: list[ProbeInvocationReport] = []
        self.acp_handshake_log: list[dict[str, Any]] = []
        self._workspace_root = Path(str(workspace_root)) if workspace_root else Path(tempfile.gettempdir())
        self._workspace_root.mkdir(parents=True, exist_ok=True)
        self._running = False

    # -- bookkeeping ----------------------------------------------------

    def _begin(self, *, consumes_budget: bool) -> None:
        if self._running:
            raise ProbeAlreadyRunning("A probe is already running; probes must be run serially.")
        if consumes_budget and self.used_real_invocations >= self.max_real_invocations:
            raise InvocationBudgetExceeded(
                f"Real-invocation budget exhausted ({self.used_real_invocations}/{self.max_real_invocations})."
            )
        self._running = True

    def _end(self, *, consumes_budget: bool) -> None:
        self._running = False
        if consumes_budget:
            self.used_real_invocations += 1

    def _new_workspace(self, label: str) -> Path:
        safe_label = "".join(c if c.isalnum() else "_" for c in label)[:40]
        return Path(tempfile.mkdtemp(prefix=f"admissible_cbp_{safe_label}_", dir=str(self._workspace_root)))

    # -- direct probe -----------------------------------------------------

    def run_direct_probe(
        self,
        *,
        label: str,
        instruction_text: str,
        timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
        command: str | None = None,
        attempt_number: int = 1,
        retry_of_probe_id: str | None = None,
    ) -> ProbeInvocationReport:
        """Invoke the raw Cursor CLI directly, independent of the adapter."""
        self._begin(consumes_budget=True)
        try:
            probe_id = f"direct_{uuid.uuid4().hex[:10]}"
            resolved_command = command or shutil.which(CURSOR_AGENT_CLI_COMMAND)
            agent_ws = self._new_workspace(label)
            (agent_ws / ".admissible").mkdir(parents=True, exist_ok=True)
            instruction_file = (agent_ws / ".admissible" / "next-agent-instruction.md").resolve()
            instruction_file.write_text(instruction_text, encoding="utf-8")

            if not resolved_command:
                report = ProbeInvocationReport(
                    probe_id=probe_id,
                    label=label,
                    path=PROBE_PATH_DIRECT,
                    attempt_number=attempt_number,
                    retry_of_probe_id=retry_of_probe_id,
                    instruction_sha256=_sha256_text(instruction_text),
                    instruction_byte_length=len(instruction_text.encode("utf-8")),
                    command=command or CURSOR_AGENT_CLI_COMMAND,
                    model_label=None,
                    timeout_seconds=timeout_seconds,
                    process_started=False,
                    process_started_at=None,
                    pid=None,
                    first_stdout_byte_at=None,
                    first_stdout_byte_elapsed_ms=None,
                    first_stderr_byte_at=None,
                    first_stderr_byte_elapsed_ms=None,
                    process_exit_code=None,
                    process_exit_at=None,
                    total_duration_ms=None,
                    timed_out=False,
                    stdout_byte_count=0,
                    stderr_byte_count=0,
                    stdout_preview=None,
                    stderr_preview=None,
                    response_sha256=None,
                    usable_response_detected=False,
                    classification=PROBE_STATUS_WRAPPER_FAILURE,
                    error_message="cursor-agent command not found on PATH",
                    process_tree=None,
                    cancellation_cleanup_failure=False,
                )
                self.probe_log.append(report)
                return report

            prompt = build_cursor_agent_file_pointer_adapter(instruction_file)
            adapter_error = validate_cursor_agent_file_pointer_adapter(prompt)
            if adapter_error:
                raise ValueError(adapter_error)

            argv = [resolved_command]
            for token in cursor_agent_cli_safe_args_template():
                token = token.replace("{agent_workspace}", str(agent_ws))
                token = token.replace("{prompt}", prompt)
                argv.append(token)

            env, env_diag = build_cursor_agent_safe_environment()
            if env is None:
                raise RuntimeError(f"safe environment blocked: {env_diag}")

            capture = _run_with_incremental_capture(
                argv, cwd=str(agent_ws), env=env, timeout_seconds=timeout_seconds
            )
            response_text = capture.stdout.strip() if not capture.wrapper_error else None
            classification = _classify(capture, response_text)
            report = ProbeInvocationReport(
                probe_id=probe_id,
                label=label,
                path=PROBE_PATH_DIRECT,
                attempt_number=attempt_number,
                retry_of_probe_id=retry_of_probe_id,
                instruction_sha256=_sha256_text(instruction_text),
                instruction_byte_length=len(instruction_text.encode("utf-8")),
                command=resolved_command,
                model_label=None,
                timeout_seconds=timeout_seconds,
                process_started=capture.process_started,
                process_started_at=capture.process_started_at,
                pid=capture.pid,
                first_stdout_byte_at=capture.first_stdout_byte_at,
                first_stdout_byte_elapsed_ms=capture.first_stdout_byte_elapsed_ms,
                first_stderr_byte_at=capture.first_stderr_byte_at,
                first_stderr_byte_elapsed_ms=capture.first_stderr_byte_elapsed_ms,
                process_exit_code=capture.process_exit_code,
                process_exit_at=capture.process_exit_at,
                total_duration_ms=capture.total_duration_ms,
                timed_out=capture.timed_out,
                stdout_byte_count=len(capture.stdout.encode("utf-8")),
                stderr_byte_count=len(capture.stderr.encode("utf-8")),
                stdout_preview=_redact_preview(capture.stdout),
                stderr_preview=_redact_preview(capture.stderr),
                response_sha256=_sha256_text(response_text) if response_text else None,
                usable_response_detected=classification == PROBE_STATUS_SUCCESS,
                classification=classification,
                error_message=capture.wrapper_error,
                process_tree=capture.process_tree.to_dict() if capture.process_tree else None,
                cancellation_cleanup_failure=capture.cancellation_cleanup_failure,
            )
            self.probe_log.append(report)
            return report
        finally:
            self._end(consumes_budget=True)

    # -- adapter probe ------------------------------------------------------

    def run_adapter_probe(
        self,
        *,
        label: str,
        instruction_text: str,
        timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
        command: str | None = None,
        attempt_number: int = 1,
        retry_of_probe_id: str | None = None,
    ) -> ProbeInvocationReport:
        """Invoke the real production ``CursorCliAgentBackend`` with an
        injected low-level runner, so production argv/env/validation logic
        runs unmodified while the harness still observes the subprocess
        boundary directly (incremental timing, process tree).
        """
        self._begin(consumes_budget=True)
        try:
            probe_id = f"adapter_{uuid.uuid4().hex[:10]}"
            target_ws = self._new_workspace(f"{label}_target")
            agent_ws = self._new_workspace(f"{label}_agent")

            config = CursorCliConfig.cursor_agent_preset(command or CURSOR_AGENT_CLI_COMMAND)
            capture_holder: dict[str, SubprocessCaptureResult] = {}

            def _adapter_runner(argv: list[str], **kwargs: Any) -> Any:
                capture = _run_with_incremental_capture(
                    argv,
                    cwd=str(kwargs.get("cwd")),
                    env=dict(kwargs.get("env") or {}),
                    timeout_seconds=float(kwargs.get("timeout") or timeout_seconds),
                    input_text=kwargs.get("input"),
                )
                capture_holder["capture"] = capture
                if capture.timed_out:
                    raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))
                return subprocess.CompletedProcess(
                    args=argv,
                    returncode=capture.process_exit_code if capture.process_exit_code is not None else -1,
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                )

            backend = CursorCliAgentBackend(config=config, runner=_adapter_runner)
            request = AgentInvocationRequest(
                instruction_text=instruction_text,
                session_id="run_046_probe",
                turn_number=1,
                instruction_id=probe_id,
                target_workspace_path=str(target_ws),
                agent_workspace_path=str(agent_ws),
                timeout_seconds=timeout_seconds,
            )
            invoke_result = backend.invoke(request)
            capture = capture_holder.get("capture")

            if capture is None:
                # invoke() short-circuited (e.g. blocked_by_configuration) before
                # ever reaching the runner -- no subprocess was spawned at all.
                report = ProbeInvocationReport(
                    probe_id=probe_id,
                    label=label,
                    path=PROBE_PATH_ADAPTER,
                    attempt_number=attempt_number,
                    retry_of_probe_id=retry_of_probe_id,
                    instruction_sha256=_sha256_text(instruction_text),
                    instruction_byte_length=len(instruction_text.encode("utf-8")),
                    command=config.resolved_command(),
                    model_label=config.model_label,
                    timeout_seconds=timeout_seconds,
                    process_started=False,
                    process_started_at=invoke_result.started_at,
                    pid=None,
                    first_stdout_byte_at=None,
                    first_stdout_byte_elapsed_ms=None,
                    first_stderr_byte_at=None,
                    first_stderr_byte_elapsed_ms=None,
                    process_exit_code=None,
                    process_exit_at=invoke_result.completed_at,
                    total_duration_ms=invoke_result.invocation_duration_ms,
                    timed_out=False,
                    stdout_byte_count=0,
                    stderr_byte_count=0,
                    stdout_preview=None,
                    stderr_preview=None,
                    response_sha256=None,
                    usable_response_detected=False,
                    classification=PROBE_STATUS_WRAPPER_FAILURE,
                    error_message=invoke_result.error_message,
                    process_tree=None,
                    cancellation_cleanup_failure=False,
                    adapter_invoke_status=invoke_result.status,
                )
                self.probe_log.append(report)
                return report

            response_text = invoke_result.response_text
            classification = _classify(capture, response_text)
            report = ProbeInvocationReport(
                probe_id=probe_id,
                label=label,
                path=PROBE_PATH_ADAPTER,
                attempt_number=attempt_number,
                retry_of_probe_id=retry_of_probe_id,
                instruction_sha256=_sha256_text(instruction_text),
                instruction_byte_length=len(instruction_text.encode("utf-8")),
                command=config.resolved_command(),
                model_label=config.model_label,
                timeout_seconds=timeout_seconds,
                process_started=capture.process_started,
                process_started_at=capture.process_started_at,
                pid=capture.pid,
                first_stdout_byte_at=capture.first_stdout_byte_at,
                first_stdout_byte_elapsed_ms=capture.first_stdout_byte_elapsed_ms,
                first_stderr_byte_at=capture.first_stderr_byte_at,
                first_stderr_byte_elapsed_ms=capture.first_stderr_byte_elapsed_ms,
                process_exit_code=capture.process_exit_code,
                process_exit_at=capture.process_exit_at,
                total_duration_ms=capture.total_duration_ms,
                timed_out=capture.timed_out,
                stdout_byte_count=len(capture.stdout.encode("utf-8")),
                stderr_byte_count=len(capture.stderr.encode("utf-8")),
                stdout_preview=_redact_preview(capture.stdout),
                stderr_preview=_redact_preview(capture.stderr),
                response_sha256=_sha256_text(response_text) if response_text else None,
                usable_response_detected=classification == PROBE_STATUS_SUCCESS,
                classification=classification,
                error_message=invoke_result.error_message,
                process_tree=capture.process_tree.to_dict() if capture.process_tree else None,
                cancellation_cleanup_failure=capture.cancellation_cleanup_failure,
                adapter_invoke_status=invoke_result.status,
            )
            self.probe_log.append(report)
            return report
        finally:
            self._end(consumes_budget=True)

    # -- ACP handshake probe (non-model; does not consume the budget) -------

    def run_acp_handshake_probe(
        self,
        *,
        label: str = "acp_handshake",
        command: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
        """Start ``cursor-agent acp`` and attempt one JSON-RPC ``initialize``
        handshake over stdio. Never sends a ``session/prompt`` or any other
        model-invoking request, so this never consumes the real-invocation
        budget. Always tears the server down afterward.
        """
        self._begin(consumes_budget=False)
        try:
            resolved_command = command or shutil.which(CURSOR_AGENT_CLI_COMMAND)
            record: dict[str, Any] = {
                "label": label,
                "started_at": _now_iso(),
                "command": resolved_command,
            }
            if not resolved_command:
                record.update({"acp_server_started": False, "error": "cursor-agent command not found"})
                self.acp_handshake_log.append(record)
                return record

            agent_ws = self._new_workspace(label)
            env, env_diag = build_cursor_agent_safe_environment()
            if env is None:
                record.update({"acp_server_started": False, "error": f"safe environment blocked: {env_diag}"})
                self.acp_handshake_log.append(record)
                return record

            argv = [resolved_command, "acp"]
            request_line = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": 1, "clientCapabilities": {}},
                }
            ) + "\n"

            started_clock = time.perf_counter()
            try:
                proc = subprocess.Popen(
                    argv,
                    shell=False,
                    cwd=str(agent_ws),
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
            except (OSError, ValueError) as exc:
                record.update({"acp_server_started": False, "error": f"{type(exc).__name__}: {exc}"})
                self.acp_handshake_log.append(record)
                return record

            record["acp_server_started"] = True
            record["pid"] = proc.pid
            response_lines: list[str] = []
            stderr_lines: list[str] = []

            def _read_one_line() -> None:
                try:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if line:
                        response_lines.append(line)
                except Exception:
                    pass

            def _drain_stderr() -> None:
                try:
                    for line in iter(proc.stderr.readline, "") if proc.stderr else []:
                        stderr_lines.append(line)
                        if len(stderr_lines) > 200:
                            break
                except Exception:
                    pass

            reader = threading.Thread(target=_read_one_line, daemon=True)
            stderr_reader = threading.Thread(target=_drain_stderr, daemon=True)
            reader.start()
            stderr_reader.start()

            try:
                if proc.stdin is not None:
                    proc.stdin.write(request_line)
                    proc.stdin.flush()
            except Exception as exc:
                record["stdin_write_error"] = f"{type(exc).__name__}: {exc}"

            reader.join(timeout=timeout_seconds)
            record["handshake_elapsed_ms"] = round((time.perf_counter() - started_clock) * 1000, 3)
            record["response_line_received"] = bool(response_lines)
            raw_line = response_lines[0].strip() if response_lines else None
            record["raw_response_preview"] = _redact_preview(raw_line)

            parsed_ok = False
            has_matching_id = False
            if raw_line:
                try:
                    parsed = json.loads(raw_line)
                    parsed_ok = True
                    has_matching_id = parsed.get("id") == 1 and parsed.get("jsonrpc") == "2.0"
                    record["response_has_result_or_error"] = ("result" in parsed) or ("error" in parsed)
                except Exception:
                    parsed_ok = False
            record["response_is_valid_jsonrpc"] = parsed_ok
            record["response_id_matches_request"] = has_matching_id

            record["process_tree"] = tree_kill(proc.pid).to_dict()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass
            record["stderr_preview"] = _redact_preview("".join(stderr_lines)) if stderr_lines else None

            self.acp_handshake_log.append(record)
            return record
        finally:
            self._end(consumes_budget=False)

    # -- reporting ------------------------------------------------------

    def to_report(self) -> dict[str, Any]:
        return {
            "generated_at": _now_iso(),
            "budget": {
                "max_real_invocations": self.max_real_invocations,
                "used_real_invocations": self.used_real_invocations,
            },
            "probes": [p.to_dict() for p in self.probe_log],
            "acp_handshake_probes": list(self.acp_handshake_log),
        }

    def write_report(self, path: str | Path) -> Path:
        out_path = Path(str(path))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(self.to_report(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        return out_path


__all__ = [
    "PROBE_STATUS_SUCCESS",
    "PROBE_STATUS_EMPTY_SUCCESS",
    "PROBE_STATUS_TIMEOUT_BEFORE_ANY_OUTPUT",
    "PROBE_STATUS_TIMEOUT_AFTER_PARTIAL_OUTPUT",
    "PROBE_STATUS_NONZERO_EXIT",
    "PROBE_STATUS_WRAPPER_FAILURE",
    "PROBE_STATUS_PARSE_FAILURE",
    "PROBE_STATUS_CODES",
    "PROBE_PATH_DIRECT",
    "PROBE_PATH_ADAPTER",
    "DEFAULT_MAX_REAL_INVOCATIONS",
    "DEFAULT_PROBE_TIMEOUT_SECONDS",
    "InvocationBudgetExceeded",
    "ProbeAlreadyRunning",
    "ProcessTreeSnapshot",
    "SubprocessCaptureResult",
    "ProbeInvocationReport",
    "CallableBackendProbeHarness",
    "tree_kill",
]
