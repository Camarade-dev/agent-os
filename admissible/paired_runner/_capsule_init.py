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

This init also installs the per-command resource bounds.  They are applied in
the forked child immediately before ``execv``, which is the only point at which
they can bound the command without also bounding this supervisor: an address
space or process limit imposed on init itself would stop init from reaping.  The
bounds arrive as one canonical JSON argument because this package is not mounted
inside the capsule and cannot be imported here, and the exact values that were
applied -- read back from the kernel, not from the request -- are reported in the
status document so the durable observation records what was enforced.

Nothing here interprets policy, contacts a provider, or touches evidence.  The
durable evidence root is never mounted into the capsule, so this process cannot
name it.
"""

from __future__ import annotations

import errno
import json
import os
import resource
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
#: Bound on what the pre-exec child may report back through the exec pipe.
MAX_CHILD_REPORT_BYTES = 4096


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


#: The bounds this init applies, mapped to their kernel resources.  Every one is
#: enforced by the kernel against the command, not by the command's cooperation.
_LIMIT_RESOURCES: tuple[tuple[str, int], ...] = (
    ("max_processes", resource.RLIMIT_NPROC),
    ("max_address_space_bytes", resource.RLIMIT_AS),
    ("max_cpu_seconds", resource.RLIMIT_CPU),
    ("max_open_files", resource.RLIMIT_NOFILE),
    ("max_file_size_bytes", resource.RLIMIT_FSIZE),
    ("core_dump_bytes", resource.RLIMIT_CORE),
)


def _report(descriptor: int, record: dict[str, object]) -> None:
    """Write one newline-terminated JSON line to the pre-exec report pipe."""

    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
    except OSError:  # pragma: no cover - the parent observes the absence
        pass


def _apply_resource_bounds(bounds: dict[str, int]) -> dict[str, object]:
    """Apply every bound in the forked child and read back what the kernel holds.

    A bound that cannot be set is fatal to the child: running the command with
    one limit silently missing would make the durable observation a false
    statement about what contained it.
    """

    applied: dict[str, object] = {}
    for name, which in _LIMIT_RESOURCES:
        value = int(bounds[name])
        # RLIMIT_CPU's soft limit raises SIGXCPU and its hard limit SIGKILLs, so
        # the hard limit is deliberately one second later; every other bound is
        # set hard and soft alike so nothing can raise it back.
        hard = value + 1 if which == resource.RLIMIT_CPU else value
        resource.setrlimit(which, (value, hard))
        applied[name] = list(resource.getrlimit(which))
    return applied


def main(argv: list[str]) -> int:
    if len(argv) < 6:
        return 2
    status_fd = int(argv[1])
    control_fd = int(argv[2])
    timeout_ms = int(argv[3])
    bounds = json.loads(argv[4])
    command = argv[5:]

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
    #
    # The same pipe carries the resource bounds the kernel actually holds.  The
    # child reads them back with getrlimit after setting them and writes them
    # here before exec, so the durable observation reports an enforced limit
    # rather than a requested one.
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
        bounded = False
        try:
            os.set_inheritable(exec_write, False)  # close-on-exec
            # The bounds are applied here, in the child, so this supervisor keeps
            # the address space and process budget it needs to reap.  A bound
            # that cannot be set stops the command before it exists.
            _report(exec_write, {"limits": _apply_resource_bounds(bounds)})
            bounded = True
            os.execv(command[0], command)
        except OSError as error:
            _report(exec_write, {"exec_errno" if bounded else "limit_errno": error.errno})
            if not bounded:
                os._exit(125)
            os._exit(126 if error.errno == errno.EACCES else 127)
        except (KeyError, TypeError, ValueError) as error:  # malformed bounds
            _report(exec_write, {"limit_error": type(error).__name__})
            os._exit(125)
        os._exit(127)  # pragma: no cover - execv either replaces or raises

    # Read the exec status before supervising.  EOF means execv succeeded.
    os.close(exec_write)
    exec_errno: int | None = None
    limit_errno: int | None = None
    applied_limits: object | None = None
    try:
        chunks: list[bytes] = []
        while len(b"".join(chunks)) < MAX_CHILD_REPORT_BYTES:
            chunk = os.read(exec_read, 512)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        for line in raw.decode("utf-8", "replace").splitlines():
            if not line:
                continue
            record = json.loads(line)
            if "limits" in record:
                applied_limits = record["limits"]
            if "exec_errno" in record:
                exec_errno = int(record["exec_errno"])
            if "limit_errno" in record:
                limit_errno = int(record["limit_errno"])
            if "limit_error" in record:
                limit_errno = -1
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
            # What the kernel actually held, read back with getrlimit inside the
            # bounded child rather than echoed from the request.
            "resource_limits_applied": applied_limits is not None and limit_errno is None,
            "resource_limits": applied_limits,
            "resource_limit_failure_errno": limit_errno,
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
