"""Provider-neutral managed-process lifecycle (slice ADMISSIBLE_RUN_047).

RUN_046 confirmed a real, load-bearing defect shared by *every* external
backend process Admissible spawns on Windows: ``cursor-agent`` resolves through
a ``.CMD`` -> ``powershell.exe`` -> ``node.exe`` chain, and
``subprocess.run(timeout=...)``'s own cleanup on ``TimeoutExpired`` only
terminates the *direct* child. ``powershell.exe`` and ``node.exe`` (the process
actually holding the model connection) are left running, orphaned, after every
timeout. This module owns the process tree so a timeout/cancel deterministically
terminates the whole chain and *proves* the cleanup with a post-termination
liveness check.

Design constraints honored here (RUN_047 hard constraints):

- ``shell=False`` always; the executable and argv are fixed/backend-owned and
  never taken from a session, model, or UI.
- Windows uses a **Job Object** with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` so
  descendants inherit containment and a single ``TerminateJobObject`` kills the
  whole tree deterministically; a ``psutil`` recursive tree-kill is the fallback
  when the Job Object cannot be created, and cleanup is *verified* either way.
- POSIX starts a dedicated session/process-group (``start_new_session=True``)
  and terminates the entire group (``SIGTERM`` then ``SIGKILL``).
- Cleanup is always *verified* (owned pids re-checked for liveness); if it
  cannot be proven complete the caller is told, so a circuit breaker can refuse
  to auto-retry and force explicit operator recovery.
- All OS specifics sit behind an injectable ``ContainmentStrategy`` /
  ``spawn`` seam so the deterministic unit suite never spawns a real process.

Nothing here calls a model provider, and nothing here is Cursor-specific.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Any, Callable

try:  # soft dependency; degrade to os-level checks when unavailable
    import psutil
except ImportError:  # pragma: no cover - environment without psutil installed
    psutil = None  # type: ignore[assignment]


# -- platform-strategy identifiers -------------------------------------------
PLATFORM_STRATEGY_WINDOWS_JOB = "windows_job_object"
PLATFORM_STRATEGY_WINDOWS_TREE_KILL = "windows_psutil_tree_kill"
PLATFORM_STRATEGY_POSIX_SESSION = "posix_process_session"
PLATFORM_STRATEGY_PSUTIL_TREE_KILL = "psutil_tree_kill"
PLATFORM_STRATEGY_FAKE = "fake_containment"
PLATFORM_STRATEGY_NONE = "none"

# -- termination reasons -----------------------------------------------------
TERMINATION_COMPLETED = "completed"  # process exited on its own
TERMINATION_GRACEFUL_STOP = "graceful_stop"
TERMINATION_HARD_TIMEOUT = "hard_timeout"
TERMINATION_CANCELLED = "cancelled"
TERMINATION_CLEANUP_FAILED = "cleanup_failed"
TERMINATION_SPAWN_FAILED = "spawn_failed"
TERMINATION_NOT_STARTED = "not_started"

_DEFAULT_GRACE_SECONDS = 5.0
_DEFAULT_FORCE_SECONDS = 5.0
_DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Durable result value object (PART A.4)
# ---------------------------------------------------------------------------


@dataclass
class ManagedProcessResult:
    """Durable, bounded lifecycle record for one managed process.

    Persisting this on an invocation record lets an operator see *proof* that a
    timeout/cancel actually terminated the whole tree (``cleanup_complete`` +
    ``remaining_process_ids``), not just that Admissible asked it to.
    """

    process_id: int | None = None
    observed_descendant_ids: list[int] = field(default_factory=list)
    started_at: str | None = None
    first_stdout_at: str | None = None
    first_stderr_at: str | None = None
    exited_at: str | None = None
    exit_code: int | None = None
    termination_reason: str = TERMINATION_NOT_STARTED
    graceful_termination_attempted: bool = False
    force_termination_attempted: bool = False
    cleanup_complete: bool = True
    remaining_process_ids: list[int] = field(default_factory=list)
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    output_truncated: bool = False
    platform_strategy: str = PLATFORM_STRATEGY_NONE

    @property
    def cleanup_proven(self) -> bool:
        """True only when the managed tree is proven gone (circuit-breaker input)."""
        return self.cleanup_complete and not self.remaining_process_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_id": self.process_id,
            "observed_descendant_ids": list(self.observed_descendant_ids),
            "started_at": self.started_at,
            "first_stdout_at": self.first_stdout_at,
            "first_stderr_at": self.first_stderr_at,
            "exited_at": self.exited_at,
            "exit_code": self.exit_code,
            "termination_reason": self.termination_reason,
            "graceful_termination_attempted": self.graceful_termination_attempted,
            "force_termination_attempted": self.force_termination_attempted,
            "cleanup_complete": self.cleanup_complete,
            "cleanup_proven": self.cleanup_proven,
            "remaining_process_ids": list(self.remaining_process_ids),
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "output_truncated": self.output_truncated,
            "platform_strategy": self.platform_strategy,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ManagedProcessResult | None":
        if not data:
            return None
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class TreeTerminationOutcome:
    """What a containment strategy observed while terminating a tree."""

    observed_descendant_ids: list[int] = field(default_factory=list)
    remaining_process_ids: list[int] = field(default_factory=list)
    strategy: str = PLATFORM_STRATEGY_NONE

    @property
    def cleanup_complete(self) -> bool:
        return not self.remaining_process_ids


# ---------------------------------------------------------------------------
# Liveness probe (used for cleanup verification)
# ---------------------------------------------------------------------------


def pid_alive(pid: int | None) -> bool:
    """Best-effort cross-platform liveness check for cleanup verification.

    Conservative: when a pid's state cannot be determined it is reported *alive*
    so the circuit breaker never falsely claims a clean tree. Pid reuse within
    the short cleanup window is accepted as a bounded risk (the Job Object /
    process group is the primary mechanism; this only *proves* the outcome).
    """
    if pid is None or pid <= 0:
        return False
    if psutil is not None:
        try:
            proc = psutil.Process(pid)
            return proc.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False
        except psutil.Error:
            return True
    if os.name == "nt":  # pragma: no cover - exercised only on real Windows
        return _windows_pid_alive(pid)
    try:  # POSIX
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _windows_pid_alive(pid: int) -> bool:  # pragma: no cover - real Windows only
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    SYNCHRONIZE = 0x00100000
    STILL_ACTIVE = 259
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if not handle:
        return False
    try:
        # WaitForSingleObject: WAIT_TIMEOUT (0x102) => still running.
        result = kernel32.WaitForSingleObject(handle, 0)
        return result == 0x00000102 or result == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# Containment strategies (injectable OS seam)
# ---------------------------------------------------------------------------


class ContainmentStrategy(ABC):
    """OS-specific process-tree ownership + termination.

    ``assign`` runs immediately after spawn so descendants are contained from
    birth; ``terminate_tree`` kills the whole tree and returns what remained so
    the manager can prove cleanup.
    """

    name: str = PLATFORM_STRATEGY_NONE

    def assign(self, proc: Any) -> None:  # pragma: no cover - default no-op
        """Assign ``proc`` (and future descendants) to this containment."""

    def observed_descendant_ids(self, proc: Any) -> list[int]:
        """Best-effort snapshot of descendant pids (never includes the root)."""
        if psutil is None or proc is None or getattr(proc, "pid", None) is None:
            return []
        try:
            root = psutil.Process(proc.pid)
            return [c.pid for c in root.children(recursive=True)]
        except psutil.Error:
            return []

    @abstractmethod
    def terminate_tree(
        self, proc: Any, *, grace_seconds: float, force_seconds: float
    ) -> TreeTerminationOutcome:
        """Terminate the whole tree; return observed + still-remaining pids."""

    def is_alive(self, pid: int | None) -> bool:
        return pid_alive(pid)


class PsutilTreeContainment(ContainmentStrategy):
    """Portable fallback: enumerate + kill the whole tree via psutil.

    Also the deliberate Windows fallback when a Job Object cannot be created.
    """

    name = PLATFORM_STRATEGY_PSUTIL_TREE_KILL

    def terminate_tree(
        self, proc: Any, *, grace_seconds: float, force_seconds: float
    ) -> TreeTerminationOutcome:
        pid = getattr(proc, "pid", None)
        if pid is None:
            return TreeTerminationOutcome(strategy=self.name)
        if psutil is None:
            # No psutil: kill only what we can and report the root's liveness.
            try:
                proc.kill()
            except Exception:
                pass
            remaining = [pid] if pid_alive(pid) else []
            return TreeTerminationOutcome(remaining_process_ids=remaining, strategy=self.name)
        try:
            root = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return TreeTerminationOutcome(strategy=self.name)
        try:
            members = [root, *root.children(recursive=True)]
        except psutil.Error:
            members = [root]
        observed = [p.pid for p in members if p.pid != pid]
        for member in reversed(members):  # descendants first
            try:
                member.terminate()
            except psutil.Error:
                pass
        _gone, alive = psutil.wait_procs(members, timeout=grace_seconds)
        for member in alive:
            try:
                member.kill()
            except psutil.Error:
                pass
        _gone2, still = psutil.wait_procs(alive, timeout=force_seconds)
        remaining = [p.pid for p in still if pid_alive(p.pid)]
        return TreeTerminationOutcome(
            observed_descendant_ids=observed,
            remaining_process_ids=remaining,
            strategy=self.name,
        )


class PosixSessionContainment(ContainmentStrategy):
    """POSIX: the child is spawned in its own session (``start_new_session``);
    terminate the whole process group with ``SIGTERM`` then ``SIGKILL``."""

    name = PLATFORM_STRATEGY_POSIX_SESSION

    def terminate_tree(
        self, proc: Any, *, grace_seconds: float, force_seconds: float
    ) -> TreeTerminationOutcome:
        pid = getattr(proc, "pid", None)
        if pid is None:
            return TreeTerminationOutcome(strategy=self.name)
        observed = self.observed_descendant_ids(proc)
        try:
            pgid = os.getpgid(pid)
        except (ProcessLookupError, OSError):
            pgid = pid
        self._signal_group(pgid, pid, signal.SIGTERM)
        self._wait_gone(proc, grace_seconds)
        if pid_alive(pid):
            self._signal_group(pgid, pid, signal.SIGKILL)
            self._wait_gone(proc, force_seconds)
        remaining = [p for p in [pid, *observed] if pid_alive(p)]
        return TreeTerminationOutcome(
            observed_descendant_ids=observed,
            remaining_process_ids=remaining,
            strategy=self.name,
        )

    @staticmethod
    def _signal_group(pgid: int, pid: int, sig: int) -> None:
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, OSError):
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, OSError):
                pass

    @staticmethod
    def _wait_gone(proc: Any, timeout: float) -> None:
        try:
            proc.wait(timeout=timeout)
        except Exception:
            pass


class WindowsJobContainment(ContainmentStrategy):
    """Windows: assign the spawned process to a Job Object with
    ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``.

    Descendants (``powershell.exe``, ``node.exe``, ...) inherit the job, so one
    ``TerminateJobObject`` deterministically kills the whole ``.CMD`` chain.
    Falls back to a psutil tree-kill if the Job Object API is unavailable, and
    cleanup is verified with a liveness probe either way.
    """

    name = PLATFORM_STRATEGY_WINDOWS_JOB

    def __init__(self) -> None:
        self._job_handle: Any = None
        self._kernel32: Any = None
        self._fallback = PsutilTreeContainment()
        self._assigned = False

    def assign(self, proc: Any) -> None:  # pragma: no cover - real Windows only
        try:
            self._assign_job(proc)
            self._assigned = True
        except Exception:
            # Any failure -> deterministic psutil fallback; never leave uncontained.
            self._job_handle = None
            self._assigned = False

    def _assign_job(self, proc: Any) -> None:  # pragma: no cover - real Windows only
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        JobObjectExtendedLimitInformation = 9

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            err = ctypes.get_last_error()
            kernel32.CloseHandle(job)
            raise ctypes.WinError(err)

        handle = getattr(proc, "_handle", None)
        if handle is None:
            PROCESS_TERMINATE = 0x0001
            PROCESS_SET_QUOTA = 0x0100
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            handle = kernel32.OpenProcess(
                PROCESS_TERMINATE | PROCESS_SET_QUOTA, False, proc.pid
            )
            if not handle:
                err = ctypes.get_last_error()
                kernel32.CloseHandle(job)
                raise ctypes.WinError(err)
        if not kernel32.AssignProcessToJobObject(job, int(handle)):
            err = ctypes.get_last_error()
            kernel32.CloseHandle(job)
            raise ctypes.WinError(err)
        self._job_handle = job

    def terminate_tree(
        self, proc: Any, *, grace_seconds: float, force_seconds: float
    ) -> TreeTerminationOutcome:
        pid = getattr(proc, "pid", None)
        observed = self.observed_descendant_ids(proc)
        if not self._assigned or self._job_handle is None:
            outcome = self._fallback.terminate_tree(
                proc, grace_seconds=grace_seconds, force_seconds=force_seconds
            )
            outcome.strategy = PLATFORM_STRATEGY_WINDOWS_TREE_KILL
            if observed and not outcome.observed_descendant_ids:
                outcome.observed_descendant_ids = observed
            return outcome
        # pragma: no cover - real Windows Job Object path
        try:
            self._kernel32.TerminateJobObject(self._job_handle, 1)
        except Exception:
            pass
        self._wait_gone(proc, grace_seconds)
        try:
            self._kernel32.CloseHandle(self._job_handle)
        except Exception:
            pass
        self._job_handle = None
        remaining = [p for p in [pid, *observed] if p is not None and pid_alive(p)]
        if remaining:
            # Job Object did not prove clean -> escalate to explicit tree-kill.
            fallback = self._fallback.terminate_tree(
                proc, grace_seconds=grace_seconds, force_seconds=force_seconds
            )
            remaining = fallback.remaining_process_ids
        return TreeTerminationOutcome(
            observed_descendant_ids=observed,
            remaining_process_ids=remaining,
            strategy=self.name,
        )

    @staticmethod
    def _wait_gone(proc: Any, timeout: float) -> None:  # pragma: no cover
        try:
            proc.wait(timeout=timeout)
        except Exception:
            pass


def default_containment_strategy() -> ContainmentStrategy:
    """Pick the narrowest reliable containment for the current platform."""
    if os.name == "nt":
        return WindowsJobContainment()
    if hasattr(os, "killpg"):
        return PosixSessionContainment()
    return PsutilTreeContainment()


# ---------------------------------------------------------------------------
# Spawn seam
# ---------------------------------------------------------------------------

SpawnFn = Callable[..., Any]


def _default_spawn(
    argv: list[str],
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    want_stdin: bool,
) -> Any:
    """Real spawn: ``subprocess.Popen`` with ``shell=False`` and, on POSIX, a
    dedicated session so the whole group is killable."""
    kwargs: dict[str, Any] = dict(
        shell=False,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if want_stdin else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    if os.name != "nt":
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **kwargs)


# ---------------------------------------------------------------------------
# Stream pump (bounded incremental capture)
# ---------------------------------------------------------------------------


class _StreamPump:
    """Read a text stream line-by-line into a queue, recording first-byte time
    and bounded byte accounting. Never retains an unbounded buffer for the
    interactive path (the client drains the queue as it reads)."""

    def __init__(self, stream: Any, *, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self.queue: Queue[str | None] = Queue()
        self.byte_count = 0
        self.truncated = False
        self.first_at: str | None = None
        self._retained: deque[str] = deque()
        self._retain = True
        self._started = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        if self._stream is not None:
            self._started = True
            self._thread.start()

    def _run(self) -> None:
        try:
            for line in iter(self._stream.readline, ""):
                if self.first_at is None:
                    self.first_at = _now_iso()
                encoded = len(line.encode("utf-8", errors="replace"))
                if self.byte_count + encoded > self._max_bytes:
                    self.truncated = True
                else:
                    self.byte_count += encoded
                    if self._retain:
                        self._retained.append(line)
                self.queue.put(line)
        except Exception:
            pass
        finally:
            self.queue.put(None)  # sentinel: stream closed
            try:
                self._stream.close()
            except Exception:
                pass

    def read_line(self, timeout: float | None) -> str | None:
        try:
            return self.queue.get(timeout=timeout)
        except Empty:
            return "__timeout__"

    def drained_text(self) -> str:
        return "".join(self._retained)

    def join(self, timeout: float) -> None:
        if self._started:
            self._thread.join(timeout=timeout)


# sentinel returned by read_line when the timeout elapsed with no line
READ_TIMEOUT = "__timeout__"


# ---------------------------------------------------------------------------
# ManagedProcess
# ---------------------------------------------------------------------------


class ManagedProcessError(RuntimeError):
    """Raised on a managed-process lifecycle misuse (never on child failure)."""


class ManagedProcess:
    """Own the full lifecycle of one external process tree.

    Two usage shapes:

    - interactive (ACP): ``start()``, then ``send_stdin``/``read_stdout_line``
      while the server streams JSON-RPC lines, then ``terminate`` or ``finish``.
    - one-shot: :func:`run_managed_oneshot` drives ``start`` -> drain -> wait
      -> ``terminate`` on timeout and returns a ``subprocess.run``-shaped result
      alongside the :class:`ManagedProcessResult`.

    The ``spawn`` and ``containment`` seams are injectable so the deterministic
    unit suite drives a fake process tree with zero real subprocesses.
    """

    def __init__(
        self,
        argv: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        want_stdin: bool = True,
        max_capture_bytes: int = _DEFAULT_MAX_CAPTURE_BYTES,
        grace_seconds: float = _DEFAULT_GRACE_SECONDS,
        force_seconds: float = _DEFAULT_FORCE_SECONDS,
        spawn: SpawnFn | None = None,
        containment: ContainmentStrategy | None = None,
    ) -> None:
        self.argv = list(argv)
        self.cwd = cwd
        self.env = env
        self.want_stdin = want_stdin
        self.max_capture_bytes = max_capture_bytes
        self.grace_seconds = grace_seconds
        self.force_seconds = force_seconds
        self._spawn = spawn or _default_spawn
        self._containment = containment or default_containment_strategy()

        self._proc: Any = None
        self._stdout_pump: _StreamPump | None = None
        self._stderr_pump: _StreamPump | None = None
        self._started_at: str | None = None
        self._exited_at: str | None = None
        self._exit_code: int | None = None
        self._termination_reason: str = TERMINATION_NOT_STARTED
        self._observed_descendants: list[int] = []
        self._graceful_attempted = False
        self._force_attempted = False
        self._cleanup_complete = True
        self._remaining: list[int] = []
        self._terminated = False
        self._start_clock = 0.0

    # -- lifecycle ----------------------------------------------------------

    @property
    def pid(self) -> int | None:
        return getattr(self._proc, "pid", None)

    @property
    def platform_strategy(self) -> str:
        return getattr(self._containment, "name", PLATFORM_STRATEGY_NONE)

    def start(self) -> None:
        if self._proc is not None:
            raise ManagedProcessError("ManagedProcess already started.")
        self._start_clock = time.perf_counter()
        try:
            self._proc = self._spawn(
                self.argv, cwd=self.cwd, env=self.env, want_stdin=self.want_stdin
            )
        except (OSError, ValueError) as exc:
            self._termination_reason = TERMINATION_SPAWN_FAILED
            raise ManagedProcessError(f"spawn failed: {type(exc).__name__}: {exc}") from exc
        self._started_at = _now_iso()
        # Contain the tree from birth so descendants can never escape.
        try:
            self._containment.assign(self._proc)
        except Exception:
            pass
        try:
            self._observed_descendants = list(
                self._containment.observed_descendant_ids(self._proc)
            )
        except Exception:
            self._observed_descendants = []
        self._stdout_pump = _StreamPump(
            getattr(self._proc, "stdout", None), max_bytes=self.max_capture_bytes
        )
        self._stderr_pump = _StreamPump(
            getattr(self._proc, "stderr", None), max_bytes=self.max_capture_bytes
        )
        self._stdout_pump.start()
        self._stderr_pump.start()

    def send_stdin(self, text: str) -> None:
        stdin = getattr(self._proc, "stdin", None)
        if stdin is None:
            raise ManagedProcessError("process has no stdin pipe.")
        stdin.write(text)
        stdin.flush()

    def close_stdin(self) -> None:
        stdin = getattr(self._proc, "stdin", None)
        if stdin is not None:
            try:
                stdin.close()
            except Exception:
                pass

    def read_stdout_line(self, timeout: float | None) -> str | None:
        """Return the next stdout line, ``None`` at EOF, or ``READ_TIMEOUT``."""
        if self._stdout_pump is None:
            return None
        return self._stdout_pump.read_line(timeout)

    def poll(self) -> int | None:
        if self._proc is None:
            return None
        return self._proc.poll()

    def wait(self, timeout: float | None = None) -> int | None:
        if self._proc is None:
            return None
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def finish(self, *, reason: str = TERMINATION_COMPLETED) -> None:
        """Record a natural (already-exited) completion and stop the pumps."""
        if self._terminated:
            return
        self._exit_code = self.poll()
        self._exited_at = _now_iso()
        self._termination_reason = reason
        self._join_pumps()
        # A clean exit still deserves verification that nothing was left behind.
        self._remaining = [
            p for p in [self.pid, *self._observed_descendants] if p and self._is_alive(p)
        ]
        self._cleanup_complete = not self._remaining
        self._terminated = True

    def terminate(self, *, reason: str = TERMINATION_CANCELLED) -> ManagedProcessResult:
        """Graceful-then-force terminate the whole tree and verify cleanup."""
        if self._proc is None:
            self._termination_reason = TERMINATION_NOT_STARTED
            return self.result()
        if self._terminated:
            return self.result()

        # 1) graceful: close stdin (EOF/shutdown signal for a stdio server).
        self._graceful_attempted = True
        self.close_stdin()
        self.wait(timeout=self.grace_seconds)
        # Verify the *whole* owned set, not just the root: a graceful root exit
        # does not guarantee ``powershell.exe``/``node.exe`` descendants died.
        remaining_after_graceful = [
            p for p in [self.pid, *self._observed_descendants] if p and self._is_alive(p)
        ]
        if remaining_after_graceful:
            # 2) force: kill the whole owned tree deterministically.
            self._force_attempted = True
            outcome = self._containment.terminate_tree(
                self._proc,
                grace_seconds=self.grace_seconds,
                force_seconds=self.force_seconds,
            )
            if outcome.observed_descendant_ids:
                merged = set(self._observed_descendants) | set(outcome.observed_descendant_ids)
                self._observed_descendants = sorted(merged)
            self._remaining = list(outcome.remaining_process_ids)
        else:
            self._remaining = []

        self._exit_code = self.poll()
        self._exited_at = _now_iso()
        self._cleanup_complete = not self._remaining
        self._termination_reason = (
            TERMINATION_CLEANUP_FAILED if self._remaining else reason
        )
        self._join_pumps()
        self._terminated = True
        return self.result()

    def _is_alive(self, pid: int | None) -> bool:
        try:
            return self._containment.is_alive(pid)
        except Exception:
            return pid_alive(pid)

    def _join_pumps(self) -> None:
        for pump in (self._stdout_pump, self._stderr_pump):
            if pump is not None:
                pump.join(timeout=2.0)

    # -- captured output ----------------------------------------------------

    def captured_stdout(self) -> str:
        return self._stdout_pump.drained_text() if self._stdout_pump else ""

    def captured_stderr(self) -> str:
        return self._stderr_pump.drained_text() if self._stderr_pump else ""

    def result(self) -> ManagedProcessResult:
        return ManagedProcessResult(
            process_id=self.pid,
            observed_descendant_ids=list(self._observed_descendants),
            started_at=self._started_at,
            first_stdout_at=self._stdout_pump.first_at if self._stdout_pump else None,
            first_stderr_at=self._stderr_pump.first_at if self._stderr_pump else None,
            exited_at=self._exited_at,
            exit_code=self._exit_code,
            termination_reason=self._termination_reason,
            graceful_termination_attempted=self._graceful_attempted,
            force_termination_attempted=self._force_attempted,
            cleanup_complete=self._cleanup_complete,
            remaining_process_ids=list(self._remaining),
            stdout_bytes=self._stdout_pump.byte_count if self._stdout_pump else 0,
            stderr_bytes=self._stderr_pump.byte_count if self._stderr_pump else 0,
            output_truncated=bool(
                (self._stdout_pump and self._stdout_pump.truncated)
                or (self._stderr_pump and self._stderr_pump.truncated)
            ),
            platform_strategy=self.platform_strategy,
        )


# ---------------------------------------------------------------------------
# One-shot convenience (PART A.5 — replaces subprocess.run(timeout=...))
# ---------------------------------------------------------------------------


@dataclass
class ManagedOneshotResult:
    """``subprocess.run``-shaped result plus the managed-process lifecycle proof."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    process_result: ManagedProcessResult

    @property
    def cleanup_proven(self) -> bool:
        return self.process_result.cleanup_proven


def run_managed_oneshot(
    argv: list[str],
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout_seconds: float,
    input_text: str | None = None,
    max_capture_bytes: int = _DEFAULT_MAX_CAPTURE_BYTES,
    spawn: SpawnFn | None = None,
    containment: ContainmentStrategy | None = None,
) -> ManagedOneshotResult:
    """Run ``argv`` to completion with a hard timeout and *guaranteed* tree
    cleanup. On timeout the whole process tree is terminated (not just the
    direct child) and cleanup is verified — the RUN_046 orphan-process fix.
    """
    proc = ManagedProcess(
        argv,
        cwd=cwd,
        env=env,
        want_stdin=input_text is not None,
        max_capture_bytes=max_capture_bytes,
        spawn=spawn,
        containment=containment,
    )
    proc.start()
    if input_text is not None:
        try:
            proc.send_stdin(input_text)
        except Exception:
            pass
        proc.close_stdin()

    exit_code = proc.wait(timeout=timeout_seconds)
    if exit_code is None and proc.poll() is None:
        result = proc.terminate(reason=TERMINATION_HARD_TIMEOUT)
        return ManagedOneshotResult(
            returncode=result.exit_code,
            stdout=proc.captured_stdout(),
            stderr=proc.captured_stderr(),
            timed_out=True,
            process_result=result,
        )
    proc.finish(reason=TERMINATION_COMPLETED)
    return ManagedOneshotResult(
        returncode=proc.result().exit_code if proc.result().exit_code is not None else exit_code,
        stdout=proc.captured_stdout(),
        stderr=proc.captured_stderr(),
        timed_out=False,
        process_result=proc.result(),
    )


__all__ = [
    "PLATFORM_STRATEGY_WINDOWS_JOB",
    "PLATFORM_STRATEGY_WINDOWS_TREE_KILL",
    "PLATFORM_STRATEGY_POSIX_SESSION",
    "PLATFORM_STRATEGY_PSUTIL_TREE_KILL",
    "PLATFORM_STRATEGY_FAKE",
    "TERMINATION_COMPLETED",
    "TERMINATION_GRACEFUL_STOP",
    "TERMINATION_HARD_TIMEOUT",
    "TERMINATION_CANCELLED",
    "TERMINATION_CLEANUP_FAILED",
    "TERMINATION_SPAWN_FAILED",
    "TERMINATION_NOT_STARTED",
    "READ_TIMEOUT",
    "ManagedProcessResult",
    "TreeTerminationOutcome",
    "ContainmentStrategy",
    "PsutilTreeContainment",
    "PosixSessionContainment",
    "WindowsJobContainment",
    "default_containment_strategy",
    "ManagedProcess",
    "ManagedProcessError",
    "ManagedOneshotResult",
    "run_managed_oneshot",
    "pid_alive",
]
