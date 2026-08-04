"""The init/reaper that runs as PID 1 inside the paired-runner capsule.

This file is bound read-only into the capsule at a fixed internal path and is
executed by ``bwrap --as-pid-1``.  Being PID 1 of a private PID namespace is the
whole point: every descendant the effect creates -- including one that calls
``setsid``, double-forks, or deliberately orphans itself -- is reparented *here*
and cannot leave the namespace.  Quiescence is therefore not asserted from
outside by inspecting a process group; it is derived here from ``ECHILD``, which
the kernel returns only when no process other than this init remains.

The controller learns the outcome through one dedicated status descriptor
(:data:`STATUS_FD`).  That descriptor is separate from ``stdout``/``stderr``, so
a hostile effect that closes, floods, or forges its own output streams cannot
forge, suppress, or race the process-domain observation.

Nothing here interprets policy, contacts a provider, or touches evidence.  The
durable evidence root is never mounted into the capsule, so this process cannot
name it.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import sys
import time


#: Rebound from ``argv`` in :func:`main`; only :func:`_emit` reads it.
STATUS_FD = 3

#: Ordered, documented escalation applied to the whole PID namespace.
ESCALATION_TERM = "SIGTERM_PID_NAMESPACE"
ESCALATION_KILL = "SIGKILL_PID_NAMESPACE"

#: Grace period between the namespace-wide SIGTERM and SIGKILL.
GRACE_PERIOD_MS = 2_000
#: Bound on the post-escalation reap wait so init can never hang forever.
FINAL_REAP_TIMEOUT_MS = 10_000


def _monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def _kill_namespace(signal_number: int) -> None:
    """Signal every process in this PID namespace except init itself.

    Inside a PID namespace ``kill(-1, sig)`` reaches all processes but PID 1, so
    this is the exact "terminate the whole process domain" primitive.  A
    descendant cannot escape it by changing process group or session, because
    the namespace, not the group, is the boundary.
    """

    try:
        os.kill(-1, signal_number)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _cancelled(control_fd: int) -> bool:
    """True once the controller closes the control descriptor."""

    try:
        chunk = os.read(control_fd, 1)
    except BlockingIOError:
        return False
    except OSError:
        return True
    # EOF (empty read) means the controller released its write end.
    return chunk == b""


def main(argv: list[str]) -> int:
    if len(argv) < 5:
        return 2
    status_fd = int(argv[1])
    control_fd = int(argv[2])
    timeout_ms = int(argv[3])
    command = argv[4:]

    global STATUS_FD
    STATUS_FD = status_fd
    os.set_blocking(control_fd, False)

    start_ns = time.monotonic_ns()
    deadline_ms = _monotonic_ms() + timeout_ms

    # A close-on-exec pipe distinguishes "the command ran and exited 127" from
    # "the command could never be executed".  On a successful ``execv`` the
    # write end closes automatically and the parent reads EOF; on failure the
    # child writes its errno first.  Without this the two cases are
    # indistinguishable, and a missing executable would be reported as a
    # command that ran and chose to fail.
    exec_read, exec_write = os.pipe()
    os.set_inheritable(exec_write, True)

    try:
        direct_pid = os.fork()
    except OSError as error:
        _emit({"init_error": f"fork_failed:{error.errno}"})
        return 2

    if direct_pid == 0:
        # The effect itself.  It keeps the inherited stdout/stderr pipes and
        # loses the status and control descriptors, so it can neither observe
        # nor forge the process-domain record.
        for descriptor in (status_fd, control_fd, exec_read):
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.set_blocking(exec_write, True)
        try:
            os.set_inheritable(exec_write, False)  # close-on-exec
            os.execv(command[0], command)
        except OSError as error:
            try:
                os.write(exec_write, str(error.errno).encode("ascii")[:16])
            except OSError:
                pass
            os._exit(126 if error.errno == errno.EACCES else 127)
        os._exit(127)  # pragma: no cover - execv either replaces or raises

    # Read the exec status before supervising.  EOF means execv succeeded.
    os.close(exec_write)
    exec_errno: int | None = None
    try:
        raw = os.read(exec_read, 16)
        if raw:
            exec_errno = int(raw.decode("ascii", "replace") or 0)
    except (OSError, ValueError):
        exec_errno = None
    finally:
        try:
            os.close(exec_read)
        except OSError:
            pass

    # --- supervision --------------------------------------------------------
    direct_status: int | None = None
    extra_reaped = 0
    timed_out = False
    cancelled = False
    escalation: list[str] = []
    grace_deadline_ms: int | None = None
    descendants_alive_at_direct_exit = False

    while True:
        try:
            reaped_pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            # ECHILD: no process other than this init remains in the namespace.
            # This is the physical quiescence proof.
            break
        except OSError as error:  # pragma: no cover - defensive
            _emit({"init_error": f"waitpid_failed:{error.errno}"})
            return 2

        if reaped_pid == 0:
            now_ms = _monotonic_ms()
            if grace_deadline_ms is None:
                if not timed_out and not cancelled and now_ms >= deadline_ms:
                    timed_out = True
                    escalation.append(ESCALATION_TERM)
                    _kill_namespace(signal.SIGTERM)
                    grace_deadline_ms = now_ms + GRACE_PERIOD_MS
                elif not timed_out and not cancelled and _cancelled(control_fd):
                    cancelled = True
                    escalation.append(ESCALATION_TERM)
                    _kill_namespace(signal.SIGTERM)
                    grace_deadline_ms = now_ms + GRACE_PERIOD_MS
            elif now_ms >= grace_deadline_ms and ESCALATION_KILL not in escalation:
                escalation.append(ESCALATION_KILL)
                _kill_namespace(signal.SIGKILL)
                grace_deadline_ms = now_ms + FINAL_REAP_TIMEOUT_MS
            elif ESCALATION_KILL in escalation and now_ms >= (grace_deadline_ms or 0):
                # SIGKILL is not refusable; reaching here means the kernel has
                # not yet delivered every exit.  Keep reaping rather than
                # claiming a quiescence that has not happened.
                grace_deadline_ms = now_ms + FINAL_REAP_TIMEOUT_MS
            time.sleep(0.005)
            continue

        if reaped_pid == direct_pid:
            direct_status = status
            if direct_status is not None and not timed_out and not cancelled:
                # The direct child is gone.  Anything still running is a
                # descendant that outlived its parent: exactly the case a pipe
                # EOF would have mistaken for completion.
                if _namespace_has_other_processes():
                    descendants_alive_at_direct_exit = True
                    escalation.append(ESCALATION_TERM)
                    _kill_namespace(signal.SIGTERM)
                    grace_deadline_ms = _monotonic_ms() + GRACE_PERIOD_MS
        else:
            extra_reaped += 1

    end_ns = time.monotonic_ns()

    exit_code: int | None
    terminating_signal: int | None
    if direct_status is None:  # pragma: no cover - defensive
        exit_code = None
        terminating_signal = None
    elif os.WIFSIGNALED(direct_status):
        exit_code = None
        terminating_signal = os.WTERMSIG(direct_status)
    elif os.WIFEXITED(direct_status):
        exit_code = os.WEXITSTATUS(direct_status)
        terminating_signal = None
    else:  # pragma: no cover - stopped children are impossible without WUNTRACED
        exit_code = None
        terminating_signal = None

    _emit(
        {
            "direct_exit_code": exit_code,
            "direct_terminating_signal": terminating_signal,
            "extra_descendants_reaped": extra_reaped,
            "descendants_alive_at_direct_exit": descendants_alive_at_direct_exit,
            "namespace_quiescent": True,
            "exec_failure_errno": exec_errno,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "termination_escalation": escalation,
            "init_duration_ns": end_ns - start_ns,
        }
    )
    return 0


def _namespace_has_other_processes() -> bool:
    """True when a process other than this init still exists in the namespace.

    ``kill(-1, 0)`` succeeds only when at least one signalable process other
    than PID 1 remains, so this is a kernel observation rather than a scan of
    ``/proc`` that a hostile process could try to influence.
    """

    try:
        os.kill(-1, 0)
    except ProcessLookupError:
        return False
    except OSError:  # pragma: no cover - defensive
        return False
    return True


def _emit(record: dict[str, object]) -> None:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        written = 0
        while written < len(payload):
            written += os.write(STATUS_FD, payload[written:])
        os.close(STATUS_FD)
    except OSError:  # pragma: no cover - the controller observes the absence
        pass


if __name__ == "__main__":
    sys.exit(main(sys.argv))
