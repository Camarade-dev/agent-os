"""Controller-owned deadlines and trusted process ownership (M2-B33, M2-B34).

Two defects share one root cause: the trusted controller delegated questions it
was responsible for answering to a process it does not trust to answer them.

M2-B33 -- controller-owned bounds
    Every helper round trip was a blocking read with no deadline the controller
    itself enforced.  A helper that is alive but wedged, stopped, or
    protocol-deadlocked therefore held the controller open indefinitely: no
    release classification, no local cgroup kill, no cleanup, no refusal
    evidence, no return.  A timeout implemented *by the helper* is not a bound;
    it is a promise from the thing that is failing.  :class:`Deadline` is an
    absolute monotonic instant owned by this process, and every operation that
    depends on an external process carries one.

M2-B34 -- proved ownership and reap
    The private mount-namespace helper forks the launcher, so the launcher is
    the *helper's* child and the controller's grandchild.  When the helper dies
    after the gate write, ``cgroup.kill`` still destroys the process domain and
    an empty ``cgroup.procs`` still proves no live member -- but neither says
    who observed the launcher's exit or who reaped it.  An empty cgroup is
    compatible with a launcher that some unrelated ancestor reaped, and with a
    zombie this controller cannot see.

    The smallest Linux mechanism that lets the *trusted controller* answer
    both questions is ``PR_SET_CHILD_SUBREAPER``.  The controller marks itself
    a child subreaper before the helper is forked; when the helper dies, the
    kernel reparents the orphaned launcher to the nearest subreaper ancestor,
    which is this controller.  ``waitpid`` on that exact PID then reaps it, and
    the reaper identity is this process rather than an unrelated init.

    A ``pidfd`` is opened alongside, but only for *observation*.  It is verified
    Linux behaviour, not an assumption, that ``waitid(P_PIDFD, ...)`` on a
    process that is not the caller's child fails with ``ECHILD``: a pidfd never
    grants the right to reap.  Exit observation and reap are therefore two
    distinct, separately recorded facts.

Rejected alternatives are recorded in
``implementation/M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json``.

Constraints this module holds:

* the subreaper flag is process-wide, so its lifetime is owned explicitly: it
  is acquired before the first trusted helper is forked, reference-counted
  across concurrent effects, and restored to its previous value when the last
  helper closes;
* the flag is not inherited across ``fork``, so a copy of this state carried
  into a child is detected by PID and re-derived rather than trusted;
* no reaping call is ever made over ``-1``.  Only PIDs this controller owns are
  waited on, so a concurrent unrelated child of this process is never reaped;
* every reap is recorded once.  A repeated cleanup reports the first outcome
  and never claims a second reap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
import ctypes.util
import errno
import os
import select
import threading
import time
from typing import Any


# --- controller-owned deadlines ----------------------------------------------
#
# Values are declared in milliseconds because the durable evidence encoding
# forbids floating-point values; seconds are derived where a syscall needs them.

#: The helper must acknowledge that it accepted a release request within this.
HELPER_RELEASE_ACCEPT_DEADLINE_MS = 5_000
#: ...and must report the outcome of the gate write within this.
HELPER_RELEASE_COMPLETION_DEADLINE_MS = 5_000
#: kill / poll / spawn round trips.
HELPER_CONTROL_RPC_DEADLINE_MS = 5_000
#: The controller-side margin added to a caller's own wait timeout.  The helper
#: may honour the caller's timeout; the controller does not rely on it.
HELPER_WAIT_RPC_MARGIN_MS = 2_000
#: Helper shutdown, including the failure-cleanup path.
HELPER_SHUTDOWN_DEADLINE_MS = 5_000
#: Helper start-up: unshare, uid/gid map exchange, tmpfs mount, view descriptor.
HELPER_STARTUP_DEADLINE_MS = 10_000
#: How long the controller waits to observe the launcher's exit.
LAUNCHER_EXIT_OBSERVATION_DEADLINE_MS = 5_000
#: How long the controller waits to reap the launcher once it owns it.
LAUNCHER_REAP_DEADLINE_MS = 5_000
#: How long the controller waits to reap the helper it forked.
HELPER_REAP_DEADLINE_MS = 5_000
#: The whole bounded abort path, including every step above.
ABORT_TOTAL_DEADLINE_MS = 30_000

#: Polling granularity for bounded waits.  Small enough not to dominate the
#: deadline, large enough not to spin.
_POLL_INTERVAL_SECONDS = 0.01


@dataclass(frozen=True)
class Deadline:
    """An absolute monotonic instant this controller owns.

    Absolute rather than relative: a sequence of bounded steps must not be able
    to reset its own budget, and a step that is retried must consume the same
    instant it started against.
    """

    expires_at_ns: int
    label: str = ""

    @classmethod
    def after(cls, seconds: float, label: str = "") -> "Deadline":
        return cls(time.monotonic_ns() + int(max(0.0, seconds) * 1_000_000_000), label)

    @classmethod
    def after_ms(cls, milliseconds: int, label: str = "") -> "Deadline":
        return cls.after(max(0, int(milliseconds)) / 1000.0, label)

    @classmethod
    def already_expired(cls, label: str = "") -> "Deadline":
        return cls(time.monotonic_ns(), label)

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, (self.expires_at_ns - time.monotonic_ns()) / 1_000_000_000)

    @property
    def expired(self) -> bool:
        return time.monotonic_ns() >= self.expires_at_ns

    def bounded_by(self, other: "Deadline | None") -> "Deadline":
        """The earlier of two deadlines, so a sub-step never outlives its whole."""

        if other is None:
            return self
        return self if self.expires_at_ns <= other.expires_at_ns else Deadline(
            other.expires_at_ns, self.label or other.label
        )

    def sub(self, milliseconds: int, label: str) -> "Deadline":
        """A nested deadline that can never outlive this one."""

        return Deadline.after_ms(milliseconds, label).bounded_by(self)

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "remaining_ms": int(self.remaining_seconds * 1000), "expired": self.expired}


class ControllerDeadlineExpired(RuntimeError):
    """A controller-owned deadline expired before an external process answered."""

    def __init__(self, operation: str, detail: str = "") -> None:
        super().__init__(f"{operation}:{detail}" if detail else operation)
        self.operation = operation
        self.detail = detail


# --- child-subreaper ownership -----------------------------------------------

PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37

SUBREAPER_APPLIED = "APPLIED"
SUBREAPER_RESTORED = "RESTORED"
SUBREAPER_HELD = "HELD_BY_AN_OUTER_ACQUISITION"
SUBREAPER_UNAVAILABLE = "UNAVAILABLE_ON_THIS_KERNEL"
SUBREAPER_READBACK_MISMATCH = "READBACK_MISMATCH"


def _libc() -> Any:
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def get_child_subreaper() -> tuple[int | None, str | None]:
    """Read this process's child-subreaper flag.  ``(value, error_code)``."""

    try:
        out = ctypes.c_int(0)
        if _libc().prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(out), 0, 0, 0) != 0:
            return None, errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
        return int(out.value), None
    except Exception as error:  # pragma: no cover - no prctl on this platform
        return None, type(error).__name__


def set_child_subreaper(value: int) -> str | None:
    """Set the flag.  Returns an error code, or ``None`` on success."""

    try:
        if _libc().prctl(PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(int(value)), 0, 0, 0) != 0:
            return errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
        return None
    except Exception as error:  # pragma: no cover - no prctl on this platform
        return type(error).__name__


class ChildSubreaperOwnership:
    """Process-wide subreaper state with an explicitly owned lifetime.

    The flag is genuinely process-wide, so it is never set as a side effect and
    never left set after the last trusted helper is gone.  Acquisition is
    reference-counted so concurrent effects -- which each fork their own helper
    before and after other launchers exist -- share one activation and one
    restoration.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._depth = 0
        self._previous: int | None = None
        self._owner_pid: int | None = None
        self._code: str = SUBREAPER_UNAVAILABLE
        self._detail: str = "no acquisition has been made"
        self._applied = False

    def _reset_after_fork_locked(self) -> None:
        # PR_SET_CHILD_SUBREAPER is not inherited across fork(), so a copy of
        # this object carried into a child describes a flag the child does not
        # have.  It is re-derived rather than trusted.
        if self._owner_pid is not None and self._owner_pid != os.getpid():
            self._depth = 0
            self._previous = None
            self._applied = False
            self._owner_pid = None
            self._code = SUBREAPER_UNAVAILABLE
            self._detail = "the inherited acquisition described another process and was discarded"

    def acquire(self) -> dict[str, Any]:
        """Become a child subreaper for the lifetime of the caller's helper."""

        with self._lock:
            self._reset_after_fork_locked()
            if self._depth > 0:
                self._depth += 1
                return self.state()
            previous, read_error = get_child_subreaper()
            if previous is None:
                self._code = SUBREAPER_UNAVAILABLE
                self._detail = f"PR_GET_CHILD_SUBREAPER failed: {read_error}"
                self._applied = False
                self._depth += 1
                self._owner_pid = os.getpid()
                return self.state()
            write_error = set_child_subreaper(1)
            if write_error is not None:
                self._code = SUBREAPER_UNAVAILABLE
                self._detail = f"PR_SET_CHILD_SUBREAPER failed: {write_error}"
                self._applied = False
                self._depth += 1
                self._owner_pid = os.getpid()
                return self.state()
            observed, _ = get_child_subreaper()
            if observed != 1:
                # The write reported success; the kernel disagrees.  That is a
                # claim, not an observation, and it is refused as one.
                set_child_subreaper(previous)
                self._code = SUBREAPER_READBACK_MISMATCH
                self._detail = f"PR_GET_CHILD_SUBREAPER reads {observed} after setting 1"
                self._applied = False
                self._depth += 1
                self._owner_pid = os.getpid()
                return self.state()
            self._previous = previous
            self._applied = True
            self._code = SUBREAPER_APPLIED
            self._detail = (
                f"this controller (pid {os.getpid()}) is a child subreaper; the previous value "
                f"{previous} is restored when the last trusted helper closes"
            )
            self._depth += 1
            self._owner_pid = os.getpid()
            return self.state()

    def release(self) -> dict[str, Any]:
        """Release one acquisition; restore the prior flag on the last one."""

        with self._lock:
            self._reset_after_fork_locked()
            if self._depth == 0:
                return self.state()
            self._depth -= 1
            if self._depth > 0:
                self._code = SUBREAPER_HELD
                self._detail = f"{self._depth} trusted helper acquisition(s) still hold the flag"
                return self.state()
            if self._applied and self._previous is not None:
                error = set_child_subreaper(self._previous)
                observed, _ = get_child_subreaper()
                self._code = SUBREAPER_RESTORED if error is None else SUBREAPER_READBACK_MISMATCH
                self._detail = (
                    f"the child-subreaper flag was restored to {self._previous} (observed {observed})"
                    if error is None
                    else f"restoring the child-subreaper flag failed: {error}"
                )
            self._applied = False
            self._previous = None
            return self.state()

    @property
    def active(self) -> bool:
        with self._lock:
            self._reset_after_fork_locked()
            return self._applied and self._depth > 0

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "code": self._code,
                "detail": self._detail,
                "applied": self._applied,
                "depth": self._depth,
                "previous_value": self._previous,
                "owner_pid": self._owner_pid,
            }


#: The one subreaper owner for this controller process.
CHILD_SUBREAPER = ChildSubreaperOwnership()


# --- exit observation and reap ------------------------------------------------

REAPER_TRUSTED_CONTROLLER = "TRUSTED_CONTROLLER"
REAPER_MOUNT_NAMESPACE_HELPER = "MOUNT_NAMESPACE_HELPER"
REAPER_NONE = "NONE"

REAP_ROLES = (REAPER_TRUSTED_CONTROLLER, REAPER_MOUNT_NAMESPACE_HELPER, REAPER_NONE)

#: Why an exit could not be observed or a reap could not be performed.  Each is
#: a refusal to claim, never a substitute for the claim.
REAP_NOT_OWNED = "NOT_THIS_CONTROLLERS_CHILD"
REAP_DEADLINE_EXPIRED = "CONTROLLER_DEADLINE_EXPIRED"
REAP_ALREADY_REAPED = "ALREADY_REAPED"
REAP_SUBREAPER_UNAVAILABLE = "CHILD_SUBREAPER_UNAVAILABLE"


@dataclass(frozen=True)
class ReapOutcome:
    """Who reaped one owned process, and what the kernel reported."""

    reaped: bool
    exit_code: int | None
    reaper_role: str
    reaper_pid: int | None
    detail: str
    code: str | None = None
    already_reaped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "reaped": self.reaped,
            "exit_code": self.exit_code,
            "reaper_role": self.reaper_role,
            "reaper_pid": self.reaper_pid,
            "detail": self.detail,
            "code": self.code,
            "already_reaped": self.already_reaped,
        }


def is_addressable_pid(pid: Any) -> bool:
    """Whether ``pid`` names exactly one process.

    ``0`` is this process's whole group and every negative value is a group or
    "every process we may signal".  None of them is a process this controller
    owns, so none of them is ever passed to ``kill``, ``waitpid``, or
    ``pidfd_open``.  This is the single guard that makes ``waitpid(-1)`` and
    ``kill(-1, SIGKILL)`` unreachable from this module.
    """

    return isinstance(pid, int) and not isinstance(pid, bool) and pid > 0


def open_process_descriptor(pid: int) -> tuple[int | None, str]:
    """Open a pidfd for exit *observation*.  It never grants a right to reap."""

    if not is_addressable_pid(pid):
        return None, f"{pid!r} does not name a single owned process"
    if not hasattr(os, "pidfd_open"):  # pragma: no cover - kernel below 5.3
        return None, "os.pidfd_open is unavailable on this kernel"
    try:
        return os.pidfd_open(pid, 0), ""
    except OSError as error:
        return None, f"pidfd_open({pid}) failed: {errno.errorcode.get(error.errno, error.errno)}"


def process_present(pid: int) -> bool:
    """Whether ``/proc/<pid>`` still names a process, zombie included."""

    if not is_addressable_pid(pid):
        return False
    try:
        return os.path.isdir(f"/proc/{pid}")
    except OSError:  # pragma: no cover - /proc is part of the platform contract
        return False


def process_is_zombie(pid: int) -> bool:
    """Whether ``pid`` is an unreaped zombie right now."""

    if not is_addressable_pid(pid):
        return False
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            raw = handle.read().decode("utf-8", "replace")
    except OSError:
        return False
    # The comm field may contain spaces and parentheses; the state code is the
    # first token after the final ')'.
    tail = raw.rsplit(")", 1)[-1].split()
    return bool(tail) and tail[0] == "Z"


def observe_process_exit(descriptor: int | None, pid: int, deadline: Deadline) -> tuple[bool, str]:
    """Wait, boundedly, for ``pid`` to terminate.  ``(observed, detail)``.

    A pidfd is the exact answer where one exists: it becomes readable when the
    process terminates, whether or not this process is its parent.  Where the
    kernel offers none, ``/proc`` presence is polled instead and the weaker
    evidence is named in the detail rather than presented as the same fact.
    """

    if descriptor is None and not is_addressable_pid(pid):
        return False, f"{pid!r} does not name a single owned process; no exit can be observed"
    if descriptor is not None:
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        while True:
            remaining = deadline.remaining_seconds
            events = poller.poll(int(min(remaining, 0.25) * 1000))
            if events:
                return True, f"pidfd for {pid} reported termination"
            if deadline.expired:
                return False, f"pidfd for {pid} reported no termination before the controller deadline"
    while True:
        if not process_present(pid) or process_is_zombie(pid):
            return True, f"/proc/{pid} reports the process is gone or a zombie awaiting reap"
        if deadline.expired:
            return False, f"/proc/{pid} still reports a live process at the controller deadline"
        time.sleep(_POLL_INTERVAL_SECONDS)


def signal_process(pid: int, signal_number: int) -> dict[str, Any]:
    """Signal exactly one PID this controller owns, with no helper involved."""

    evidence: dict[str, Any] = {"pid": pid, "signal": int(signal_number), "delivered": False, "error": None}
    if not is_addressable_pid(pid):
        # kill(0, ...) signals this whole process group and kill(-1, ...) signals
        # every process this user may reach.  Neither is a process we own.
        evidence["error"] = "NOT_AN_ADDRESSABLE_PID"
        return evidence
    try:
        os.kill(pid, int(signal_number))
        evidence["delivered"] = True
    except ProcessLookupError:
        evidence["error"] = "ESRCH"
    except OSError as error:
        evidence["error"] = errno.errorcode.get(error.errno, str(error.errno))
    return evidence


def reap_owned_child(pid: int, deadline: Deadline, *, role: str = REAPER_TRUSTED_CONTROLLER) -> ReapOutcome:
    """Reap exactly ``pid``, boundedly, and record who did it.

    ``waitpid`` is called on this exact PID and never on ``-1``, so a concurrent
    unrelated child of this controller cannot be consumed here.  ``ECHILD``
    before the deadline is not failure: it is the ordinary state while an
    orphan is still being reparented to this subreaper.  ``ECHILD`` *at* the
    deadline is reported as "not this controller's child", never as a reap.
    """

    if not is_addressable_pid(pid):
        # waitpid(-1) and waitpid(0) reap *any* child, including a concurrent
        # unrelated one this controller does not own.  They are unreachable.
        return ReapOutcome(
            reaped=False,
            exit_code=None,
            reaper_role=REAPER_NONE,
            reaper_pid=None,
            detail=f"{pid!r} does not name a single owned process; waitpid over -1 or 0 is forbidden",
            code=REAP_NOT_OWNED,
        )
    last_detail = ""
    while True:
        try:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            last_detail = f"{pid} is not a child of this controller (ECHILD)"
            if deadline.expired:
                return ReapOutcome(
                    reaped=False,
                    exit_code=None,
                    reaper_role=REAPER_NONE,
                    reaper_pid=None,
                    detail=last_detail,
                    code=REAP_NOT_OWNED,
                )
            time.sleep(_POLL_INTERVAL_SECONDS)
            continue
        except OSError as error:  # pragma: no cover - defensive
            return ReapOutcome(
                reaped=False,
                exit_code=None,
                reaper_role=REAPER_NONE,
                reaper_pid=None,
                detail=f"waitpid({pid}) failed: {errno.errorcode.get(error.errno, error.errno)}",
                code=REAP_NOT_OWNED,
            )
        if waited_pid == pid:
            return ReapOutcome(
                reaped=True,
                exit_code=os.waitstatus_to_exitcode(status),
                reaper_role=role,
                reaper_pid=os.getpid(),
                detail=f"pid {os.getpid()} reaped {pid} with waitpid",
                code=None,
            )
        if deadline.expired:
            return ReapOutcome(
                reaped=False,
                exit_code=None,
                reaper_role=REAPER_NONE,
                reaper_pid=None,
                detail=f"{pid} was still running at the controller deadline",
                code=REAP_DEADLINE_EXPIRED,
            )
        time.sleep(_POLL_INTERVAL_SECONDS)


@dataclass
class ProcessOwnershipEvidence:
    """The non-collapsed lifecycle facts for one gated effect (M2-B34).

    Termination, exit observation, reap, and reaper identity are four different
    questions.  They are recorded as four different fields because an empty
    cgroup answers only the first, and a closure claim that reads the first as
    the other three is the defect this repair closes.
    """

    process_domain_kill_requested: bool = False
    process_domain_kill_mechanism: str | None = None
    launcher_pid: int | None = None
    launcher_exit_observed: bool = False
    launcher_exit_detail: str = ""
    launcher_reaped: bool = False
    launcher_exit_code: int | None = None
    launcher_reaper_role: str = REAPER_NONE
    launcher_reaper_pid: int | None = None
    launcher_reap_detail: str = ""
    launcher_reap_code: str | None = None
    launcher_zombie_remains: bool = False
    helper_pid: int | None = None
    helper_exit_observed: bool = False
    helper_reaped: bool = False
    helper_exit_code: int | None = None
    helper_reaper_role: str = REAPER_NONE
    helper_reaper_pid: int | None = None
    helper_reap_detail: str = ""
    cgroup_quiescent: bool = False
    effect_cgroup_removed: bool = False
    child_subreaper: dict[str, Any] = field(default_factory=dict)
    deadline_expirations: tuple[str, ...] = ()
    helper_bypassed: bool = False
    detail: str = ""

    def record_deadline(self, operation: str) -> None:
        if operation not in self.deadline_expirations:
            self.deadline_expirations = self.deadline_expirations + (operation,)

    def apply_launcher_reap(self, outcome: ReapOutcome) -> None:
        self.launcher_reaped = outcome.reaped
        self.launcher_exit_code = outcome.exit_code
        self.launcher_reaper_role = outcome.reaper_role
        self.launcher_reaper_pid = outcome.reaper_pid
        self.launcher_reap_detail = outcome.detail
        self.launcher_reap_code = outcome.code

    def apply_helper_reap(self, outcome: ReapOutcome) -> None:
        self.helper_reaped = outcome.reaped
        self.helper_exit_code = outcome.exit_code
        self.helper_reaper_role = outcome.reaper_role
        self.helper_reaper_pid = outcome.reaper_pid
        self.helper_reap_detail = outcome.detail

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_domain_kill_requested": self.process_domain_kill_requested,
            "process_domain_kill_mechanism": self.process_domain_kill_mechanism,
            "launcher_pid": self.launcher_pid,
            "launcher_exit_observed": self.launcher_exit_observed,
            "launcher_exit_detail": self.launcher_exit_detail,
            "launcher_reaped": self.launcher_reaped,
            "launcher_exit_code": self.launcher_exit_code,
            "launcher_reaper_role": self.launcher_reaper_role,
            "launcher_reaper_pid": self.launcher_reaper_pid,
            "launcher_reap_detail": self.launcher_reap_detail,
            "launcher_reap_code": self.launcher_reap_code,
            "launcher_zombie_remains": self.launcher_zombie_remains,
            "helper_pid": self.helper_pid,
            "helper_exit_observed": self.helper_exit_observed,
            "helper_reaped": self.helper_reaped,
            "helper_exit_code": self.helper_exit_code,
            "helper_reaper_role": self.helper_reaper_role,
            "helper_reaper_pid": self.helper_reaper_pid,
            "helper_reap_detail": self.helper_reap_detail,
            "cgroup_quiescent": self.cgroup_quiescent,
            "effect_cgroup_removed": self.effect_cgroup_removed,
            "child_subreaper": dict(self.child_subreaper),
            "deadline_expirations": list(self.deadline_expirations),
            "helper_bypassed": self.helper_bypassed,
            "detail": self.detail,
        }


def ownership_architecture_description() -> dict[str, Any]:
    """The chosen process-ownership design, stated rather than implied."""

    return {
        "chosen": "CONTROLLER_CHILD_SUBREAPER_PLUS_PIDFD_OBSERVATION",
        "why": (
            "The launcher must remain a child of the mount-namespace helper so the private tmpfs "
            "is materialised by a helper-local pathname and the gate-before-exec ordering is "
            "unchanged.  PR_SET_CHILD_SUBREAPER is the only mechanism that gives the trusted "
            "controller the right to reap that launcher when the helper dies, without changing "
            "who forks it."
        ),
        "exit_observation": "pidfd_open + poll; falls back to /proc presence and zombie state",
        "reap_right": "waitpid on the exact owned PID after subreaper reparenting",
        "verified_kernel_semantics": (
            "waitid(P_PIDFD, ...) on a process that is not the caller's child fails with ECHILD, "
            "so a pidfd alone never permits a reap; this was physically confirmed rather than "
            "assumed"
        ),
        "never": [
            "waitpid(-1)",
            "reaping a process this controller does not own",
            "treating an empty cgroup as proof that a reap occurred",
            "treating an unrelated init as the reaper of record",
            "leaving the process-wide subreaper flag set after the last trusted helper closes",
        ],
        "lifecycle": (
            "acquired before the first trusted helper is forked, reference-counted across "
            "concurrent effects, restored to its previous value when the last helper closes"
        ),
        "residual": (
            "While the flag is held, an orphaned descendant of this controller that no effect owns "
            "would reparent here and is not reaped, because reaping it would require waitpid(-1) "
            "and could consume an unrelated child.  The window is bounded by helper lifetime and "
            "is disclosed rather than closed."
        ),
    }


__all__ = [
    "ABORT_TOTAL_DEADLINE_MS",
    "CHILD_SUBREAPER",
    "ChildSubreaperOwnership",
    "ControllerDeadlineExpired",
    "Deadline",
    "HELPER_CONTROL_RPC_DEADLINE_MS",
    "HELPER_REAP_DEADLINE_MS",
    "HELPER_RELEASE_ACCEPT_DEADLINE_MS",
    "HELPER_RELEASE_COMPLETION_DEADLINE_MS",
    "HELPER_SHUTDOWN_DEADLINE_MS",
    "HELPER_STARTUP_DEADLINE_MS",
    "HELPER_WAIT_RPC_MARGIN_MS",
    "LAUNCHER_EXIT_OBSERVATION_DEADLINE_MS",
    "LAUNCHER_REAP_DEADLINE_MS",
    "PR_GET_CHILD_SUBREAPER",
    "PR_SET_CHILD_SUBREAPER",
    "ProcessOwnershipEvidence",
    "REAPER_MOUNT_NAMESPACE_HELPER",
    "REAPER_NONE",
    "REAPER_TRUSTED_CONTROLLER",
    "REAP_ALREADY_REAPED",
    "REAP_DEADLINE_EXPIRED",
    "REAP_NOT_OWNED",
    "REAP_ROLES",
    "REAP_SUBREAPER_UNAVAILABLE",
    "ReapOutcome",
    "SUBREAPER_APPLIED",
    "SUBREAPER_HELD",
    "SUBREAPER_READBACK_MISMATCH",
    "SUBREAPER_RESTORED",
    "SUBREAPER_UNAVAILABLE",
    "get_child_subreaper",
    "is_addressable_pid",
    "observe_process_exit",
    "open_process_descriptor",
    "ownership_architecture_description",
    "process_is_zombie",
    "process_present",
    "reap_owned_child",
    "set_child_subreaper",
    "signal_process",
]
