"""Bounded local process supervision for the shared effect substrate.

The readiness audit (AUD-MJ06) found that the historical one-shot path pushed
every output line into an unbounded ``queue.Queue`` while a bounded text cap
gave the appearance of safety.  This module does not reuse that architecture
and contains no queue at all.

Instead, a single controller thread multiplexes the child's ``stdout`` and
``stderr`` pipes with :mod:`selectors`.  Each stream keeps:

* a retention buffer capped at the request's ``max_output_bytes``;
* a running total byte counter for the full stream;
* an incremental SHA-256 of every byte the child produced.

Controller memory is therefore a function of the two retention caps and the
read block size, not of the total output volume.  There is no per-line object,
no list of lines, and no unbounded structure of any kind.

The module never interprets policy, never decides acceptance, and never
consults a provider.  It only starts, supervises, bounds, terminates, reaps,
and observes one local process.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import selectors
import signal
import subprocess
import threading
import time
from typing import Any, Callable

from .canonical import Fingerprint
from .observation import (
    ProcessObservation,
    ResourceObservation,
    StreamObservation,
)


try:  # pragma: no cover - resource is POSIX-only; the platform contract is POSIX
    import resource as _resource
except ImportError:  # pragma: no cover
    _resource = None


READ_BLOCK_BYTES = 65_536
#: Documented bounded controller overhead beyond the two retention caps.
CONTROLLER_FIXED_OVERHEAD_BYTES = 4 * READ_BLOCK_BYTES
STREAM_FINGERPRINT_DOMAINS = {
    "stdout": "admissible.paired_runner.m2.stream.stdout",
    "stderr": "admissible.paired_runner.m2.stream.stderr",
}
#: Ordered, documented escalation applied to the child's process group.
TERMINATION_ESCALATION_ORDER = ("SIGTERM_PROCESS_GROUP", "SIGKILL_PROCESS_GROUP")
GRACE_PERIOD_MS = 2_000
MAX_UTF8_TRIM_BYTES = 3

RESOURCE_MEASUREMENT_SEMANTICS = (
    "Child CPU time and peak RSS are read from getrusage(RUSAGE_CHILDREN) deltas taken "
    "around this exact supervision call.  RUSAGE_CHILDREN aggregates every reaped child of "
    "this controller, so the values are an upper bound attributable to this effect rather "
    "than an isolated per-process measurement; they are recorded as OBSERVED_BEST_EFFORT. "
    "controller_peak_retained_output_bytes is the exact high-water mark of bytes this "
    "controller held in its retention buffers and is OBSERVED."
)


class CancellationToken:
    """A cooperative cancellation signal owned by the caller."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class _BoundedStream:
    """Bounded retention plus full-volume accounting for one pipe."""

    def __init__(self, name: str, retention_cap: int) -> None:
        self.name = name
        self._cap = retention_cap
        self._retained = bytearray()
        self.total_bytes = 0
        self._digest = hashlib.sha256()

    def feed(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        self._digest.update(chunk)
        remaining = self._cap - len(self._retained)
        if remaining > 0:
            self._retained += chunk[:remaining]

    @property
    def retained_bytes(self) -> int:
        return len(self._retained)

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self._retained)

    def decode(self) -> tuple[str, str]:
        """Return ``(text, decode_status)`` and never guess at broken bytes."""

        raw = bytes(self._retained)
        try:
            return raw.decode("utf-8", "strict"), "UTF8_DECODED"
        except UnicodeDecodeError:
            pass
        if self.truncated:
            # A bounded cut can split one multi-byte sequence.  Trimming at most
            # three trailing bytes is the only repair permitted, and it is
            # reported distinctly from a clean decode.
            for trim in range(1, MAX_UTF8_TRIM_BYTES + 1):
                if trim > len(raw):
                    break
                try:
                    return raw[:-trim].decode("utf-8", "strict"), "UTF8_DECODED_AFTER_BOUNDARY_TRIM"
                except UnicodeDecodeError:
                    continue
        # Fail closed: the bytes are still fully counted and fingerprinted, but
        # no lossy text is presented as if the child had produced it.
        return "", "REFUSED_NON_UTF8"

    def observation(self) -> tuple[StreamObservation, str, str]:
        text, status = self.decode()
        if status == "REFUSED_NON_UTF8":
            retained = 0
            truncated = self.total_bytes > 0
        else:
            retained = len(text.encode("utf-8"))
            truncated = self.total_bytes > retained
        observation = StreamObservation.create(
            stream_name=self.name,
            total_bytes=self.total_bytes,
            retained_bytes=retained,
            retained_truncated=truncated,
            stream_fingerprint=Fingerprint(
                "sha256", STREAM_FINGERPRINT_DOMAINS[self.name], self._digest.hexdigest()
            ).validated(),
            text_decode_status=status,
        )
        return observation, text, status


@dataclass(frozen=True)
class SupervisedProcessResult:
    """The complete typed observation of one supervised local process."""

    process_observation: ProcessObservation
    stdout_observation: StreamObservation
    stderr_observation: StreamObservation
    resource_observation: ResourceObservation
    stdout_text: str
    stderr_text: str
    stdout_decode_status: str
    stderr_decode_status: str

    @property
    def refused_non_utf8(self) -> bool:
        return "REFUSED_NON_UTF8" in {self.stdout_decode_status, self.stderr_decode_status}


def _now() -> tuple[int, int]:
    return int(time.time() * 1000), time.monotonic_ns()


def _rusage_children() -> Any:
    if _resource is None:  # pragma: no cover
        return None
    return _resource.getrusage(_resource.RUSAGE_CHILDREN)


def _resource_observation(before: Any, after: Any, controller_peak: int) -> ResourceObservation:
    if before is None or after is None:  # pragma: no cover - non-POSIX host
        return ResourceObservation.create(
            child_cpu_user_ms=None,
            child_cpu_user_availability="UNAVAILABLE_ON_PLATFORM",
            child_cpu_system_ms=None,
            child_cpu_system_availability="UNAVAILABLE_ON_PLATFORM",
            child_max_rss_kib=None,
            child_max_rss_availability="UNAVAILABLE_ON_PLATFORM",
            controller_peak_retained_output_bytes=controller_peak,
            controller_peak_retained_availability="OBSERVED",
            measurement_semantics=RESOURCE_MEASUREMENT_SEMANTICS,
        )
    user_ms = max(0, int(round((after.ru_utime - before.ru_utime) * 1000)))
    system_ms = max(0, int(round((after.ru_stime - before.ru_stime) * 1000)))
    max_rss = int(after.ru_maxrss)
    return ResourceObservation.create(
        child_cpu_user_ms=user_ms,
        child_cpu_user_availability="OBSERVED_BEST_EFFORT",
        child_cpu_system_ms=system_ms,
        child_cpu_system_availability="OBSERVED_BEST_EFFORT",
        child_max_rss_kib=max_rss if max_rss >= 0 else None,
        child_max_rss_availability="OBSERVED_BEST_EFFORT" if max_rss >= 0 else "UNAVAILABLE_ON_PLATFORM",
        controller_peak_retained_output_bytes=controller_peak,
        controller_peak_retained_availability="OBSERVED",
        measurement_semantics=RESOURCE_MEASUREMENT_SEMANTICS,
    )


def supervise_command(
    *,
    argv: tuple[str, ...],
    cwd: str,
    env: dict[str, str],
    timeout_ms: int,
    max_output_bytes: int,
    cancellation: CancellationToken | None = None,
    start_hook: Callable[[], None] | None = None,
) -> SupervisedProcessResult:
    """Run one local command in its own POSIX session and observe it fully.

    The child is started with ``start_new_session=True`` so it becomes both a
    session leader and a process-group leader; every descendant that does not
    deliberately leave the group is therefore reachable by ``killpg``.  Neither
    the timeout nor cancellation can deadlock on a full pipe because both
    streams are drained continuously by the same selector loop that enforces
    them.
    """

    cancellation = cancellation or CancellationToken()
    start_wall, start_monotonic = _now()
    rusage_before = _rusage_children()

    if start_hook is not None:
        start_hook()

    try:
        process = subprocess.Popen(  # noqa: S603 - explicit argv, never a shell
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            shell=False,
        )
    except (OSError, ValueError) as error:
        end_wall, end_monotonic = _now()
        empty_stdout = _BoundedStream("stdout", max_output_bytes)
        empty_stderr = _BoundedStream("stderr", max_output_bytes)
        stdout_observation, stdout_text, stdout_status = empty_stdout.observation()
        stderr_observation, stderr_text, stderr_status = empty_stderr.observation()
        return SupervisedProcessResult(
            process_observation=ProcessObservation.create(
                process_started=False,
                child_pid=None,
                child_process_group_id=None,
                exit_code=None,
                terminating_signal=None,
                timed_out=False,
                cancelled=False,
                start_wall_clock_unix_ms=start_wall,
                end_wall_clock_unix_ms=end_wall,
                start_monotonic_ns=start_monotonic,
                end_monotonic_ns=end_monotonic,
                duration_ns=end_monotonic - start_monotonic,
                termination_escalation=(),
                descendants_reaped=True,
                start_failure_class=type(error).__name__,
            ),
            stdout_observation=stdout_observation,
            stderr_observation=stderr_observation,
            resource_observation=_resource_observation(rusage_before, _rusage_children(), 0),
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            stdout_decode_status=stdout_status,
            stderr_decode_status=stderr_status,
        )

    child_pid = process.pid
    try:
        process_group = os.getpgid(child_pid)
    except OSError:  # pragma: no cover - the child exited immediately
        process_group = child_pid

    stdout_stream = _BoundedStream("stdout", max_output_bytes)
    stderr_stream = _BoundedStream("stderr", max_output_bytes)
    streams = {process.stdout.fileno(): stdout_stream, process.stderr.fileno(): stderr_stream}
    controller_peak = 0
    timed_out = False
    cancelled = False
    escalation: list[str] = []
    deadline = start_monotonic + timeout_ms * 1_000_000

    selector = selectors.DefaultSelector()
    for pipe in (process.stdout, process.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)

    def terminate(step: str) -> None:
        escalation.append(step)
        signal_number = signal.SIGTERM if step == "SIGTERM_PROCESS_GROUP" else signal.SIGKILL
        try:
            os.killpg(process_group, signal_number)
        except (ProcessLookupError, PermissionError):
            # The group is already gone; the reap below still confirms it.
            pass

    try:
        grace_deadline: int | None = None
        while selector.get_map():
            now = time.monotonic_ns()
            if grace_deadline is None:
                if not timed_out and now >= deadline:
                    timed_out = True
                    terminate("SIGTERM_PROCESS_GROUP")
                    grace_deadline = now + GRACE_PERIOD_MS * 1_000_000
                elif not cancelled and cancellation.cancelled:
                    cancelled = True
                    terminate("SIGTERM_PROCESS_GROUP")
                    grace_deadline = now + GRACE_PERIOD_MS * 1_000_000
            elif now >= grace_deadline and "SIGKILL_PROCESS_GROUP" not in escalation:
                terminate("SIGKILL_PROCESS_GROUP")
                grace_deadline = None

            # The wait is short and bounded so timeout and cancellation stay
            # responsive while the pipes keep draining.
            for key, _ in selector.select(timeout=0.05):
                try:
                    chunk = os.read(key.fd, READ_BLOCK_BYTES)
                except BlockingIOError:  # pragma: no cover - selector said ready
                    continue
                except OSError:
                    selector.unregister(key.fileobj)
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                streams[key.fd].feed(chunk)
                controller_peak = max(
                    controller_peak, stdout_stream.retained_bytes + stderr_stream.retained_bytes
                )
    finally:
        selector.close()
        for pipe in (process.stdout, process.stderr):
            try:
                pipe.close()
            except OSError:  # pragma: no cover
                pass

    # Both pipes are at EOF, so the direct child has exited or is about to.
    # Escalate once more if it lingers, then reap unconditionally.
    try:
        process.wait(timeout=GRACE_PERIOD_MS / 1000)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        if "SIGKILL_PROCESS_GROUP" not in escalation:
            terminate("SIGKILL_PROCESS_GROUP")
        process.wait()

    if (timed_out or cancelled) and "SIGKILL_PROCESS_GROUP" not in escalation:
        # Guarantee that no descendant survives an aborted effect even when the
        # direct child answered SIGTERM promptly.
        terminate("SIGKILL_PROCESS_GROUP")

    return_code = process.returncode
    exit_code: int | None
    terminating_signal: int | None
    if return_code is not None and return_code < 0:
        exit_code = None
        terminating_signal = -return_code
    else:
        exit_code = return_code
        terminating_signal = None

    descendants_reaped = _process_group_is_empty(process_group)
    end_wall, end_monotonic = _now()
    stdout_observation, stdout_text, stdout_status = stdout_stream.observation()
    stderr_observation, stderr_text, stderr_status = stderr_stream.observation()

    return SupervisedProcessResult(
        process_observation=ProcessObservation.create(
            process_started=True,
            child_pid=child_pid,
            child_process_group_id=process_group,
            exit_code=exit_code,
            terminating_signal=terminating_signal,
            timed_out=timed_out,
            cancelled=cancelled,
            start_wall_clock_unix_ms=start_wall,
            end_wall_clock_unix_ms=end_wall,
            start_monotonic_ns=start_monotonic,
            end_monotonic_ns=end_monotonic,
            duration_ns=end_monotonic - start_monotonic,
            termination_escalation=tuple(escalation),
            descendants_reaped=descendants_reaped,
            start_failure_class=None,
        ),
        stdout_observation=stdout_observation,
        stderr_observation=stderr_observation,
        resource_observation=_resource_observation(rusage_before, _rusage_children(), controller_peak),
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        stdout_decode_status=stdout_status,
        stderr_decode_status=stderr_status,
    )


def _process_group_is_empty(process_group: int) -> bool:
    """Best-effort confirmation that nothing remains in the child's group."""

    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return True
    except PermissionError:  # pragma: no cover - a foreign process reused the id
        return False
    return False


def stream_fingerprint_of(name: str, data: bytes) -> Fingerprint:
    """Recompute a stream fingerprint in the same domain the supervisor uses."""

    if name not in STREAM_FINGERPRINT_DOMAINS:
        raise ValueError("unknown stream name")
    return Fingerprint("sha256", STREAM_FINGERPRINT_DOMAINS[name], hashlib.sha256(data).hexdigest()).validated()


def controller_memory_bound(max_output_bytes: int) -> int:
    """The documented upper bound on controller output retention, in bytes."""

    return 2 * max_output_bytes + CONTROLLER_FIXED_OVERHEAD_BYTES


__all__ = [
    "CONTROLLER_FIXED_OVERHEAD_BYTES",
    "CancellationToken",
    "GRACE_PERIOD_MS",
    "READ_BLOCK_BYTES",
    "RESOURCE_MEASUREMENT_SEMANTICS",
    "STREAM_FINGERPRINT_DOMAINS",
    "SupervisedProcessResult",
    "TERMINATION_ESCALATION_ORDER",
    "controller_memory_bound",
    "stream_fingerprint_of",
    "supervise_command",
]
