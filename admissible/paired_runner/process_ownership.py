"""Controller-owned deadlines and trusted process ownership (M2-B33, M2-B34).

Two defects share one root cause: the trusted controller delegated questions it
was responsible for answering to a process it does not trust to answer them.

The same root cause produced four further defects, closed here:

M2-B37 -- an ownership guarantee is a precondition, not a preference
    ``acquire`` reported that the process-wide flag could not be set and still
    handed back a reference, and the launch path forked anyway.  A guarantee the
    launch path is allowed to proceed without is not a guarantee.  Acquisition
    now either returns state the kernel confirmed or raises, and nothing --
    socket, fork, pidfd, helper, launcher -- is created before it succeeds.

M2-B38 -- acquisition around a fork is failure-atomic
    An acquisition taken before ``fork()`` outlived a ``fork()`` that failed, so
    a process-wide flag stayed set for a helper that was never created.  Every
    exit path between acquisition and successful ownership transfer now rolls
    the acquisition back exactly once, idempotently, after the partially created
    child is destroyed and reaped.

M2-B39 -- a restoration is a readback, not a request
    ``release`` compared the *write's* error code and reported RESTORED while
    the readback it had already performed disagreed.  Restoration is now claimed
    only when the kernel reads back exactly the intended value; every other
    outcome is a distinct, truthful residual state.

M2-B40 -- one deadline for one bounded cleanup
    Stages of the abort path started fresh fixed-duration waits after the global
    30-second deadline was exhausted.  :class:`CleanupBudget` is the single
    absolute instant a whole cleanup spends: stages receive capped *views* of it
    and never a new budget, and what each stage was granted, completed, or left
    incomplete is recorded.

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
#: How long the controller waits for a helper to exit on its own request before
#: it stops asking and kills it.  A portion of the shutdown deadline, never a
#: second budget added to it.
HELPER_COOPERATIVE_EXIT_DEADLINE_MS = 2_000
#: The subreaper release/restoration stage of a bounded cleanup.  ``prctl`` does
#: not block, so this bounds the stage's ledger entry rather than a wait.
SUBREAPER_RESTORE_DEADLINE_MS = 1_000

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
    #: The duration this deadline was *configured* with, in milliseconds.
    #: M2-B40.  An instant alone cannot answer "what total was this bounded
    #: operation given?", because by the time anything reads it some of that
    #: total has already been spent: a 30 000 ms deadline read a hair later
    #: reports 29 999 ms remaining.  The configured input is therefore carried
    #: rather than re-derived, and the remaining time is recorded separately.
    configured_ms: int | None = None

    @classmethod
    def after(cls, seconds: float, label: str = "", *, configured_ms: int | None = None) -> "Deadline":
        bounded = max(0.0, seconds)
        return cls(
            time.monotonic_ns() + int(bounded * 1_000_000_000),
            label,
            int(round(bounded * 1000)) if configured_ms is None else int(configured_ms),
        )

    @classmethod
    def after_ms(cls, milliseconds: int, label: str = "") -> "Deadline":
        exact = max(0, int(milliseconds))
        return cls.after(exact / 1000.0, label, configured_ms=exact)

    @classmethod
    def already_expired(cls, label: str = "") -> "Deadline":
        return cls(time.monotonic_ns(), label, 0)

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
        # The cap this sub-step was configured with survives being clipped: what
        # the step asked for and what it was actually granted are two facts.
        return self if self.expires_at_ns <= other.expires_at_ns else Deadline(
            other.expires_at_ns, self.label or other.label, self.configured_ms
        )

    def sub(self, milliseconds: int, label: str) -> "Deadline":
        """A nested deadline that can never outlive this one."""

        return Deadline.after_ms(milliseconds, label).bounded_by(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "configured_ms": self.configured_ms,
            "remaining_ms": int(self.remaining_seconds * 1000),
            "expired": self.expired,
        }


class ControllerDeadlineExpired(RuntimeError):
    """A controller-owned deadline expired before an external process answered."""

    def __init__(self, operation: str, detail: str = "") -> None:
        super().__init__(f"{operation}:{detail}" if detail else operation)
        self.operation = operation
        self.detail = detail


# --- M2-B40: one absolute deadline for one whole bounded cleanup --------------


@dataclass
class CleanupBudget:
    """The single instant a whole bounded cleanup spends, plus its ledger.

    A multi-stage cleanup that lets each stage start a fresh fixed-duration wait
    has no total bound at all: the stated 30 seconds becomes 30 seconds *plus*
    whatever the later stages ask for, and a caller that was promised a bounded
    abort waits for an unbounded one.  This object is created once at the entry
    to the cleanup and is the only source of time inside it.

    Stages ask for time in one of three ways, and none of them can renew the
    budget:

    * :meth:`grant` returns a :class:`Deadline` capped by this one, for a step
      that takes a deadline;
    * :meth:`grant_seconds` returns the seconds a duration-taking primitive may
      wait -- the remaining time, capped by the step's own maximum, and zero
      once the budget is spent;
    * :meth:`observe` records that a non-blocking step ran, and grants nothing.

    Every grant is recorded with the remaining budget at the moment it was
    made, so "this stage received a fresh five seconds after the deadline had
    expired" is a statement the evidence can contradict.
    """

    deadline: Deadline
    configured_total_ms: int
    default_total_ms: int = 0
    caller_supplied_deadline: bool = False
    remaining_at_entry_ms: int = 0
    started_ns: int = field(default_factory=time.monotonic_ns)
    grants: list[dict[str, Any]] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    incomplete_steps: list[str] = field(default_factory=list)

    @classmethod
    def open(cls, deadline: "Deadline | None", *, total_ms: int, label: str) -> "CleanupBudget":
        """Adopt the caller's whole deadline, or create the one and only one.

        The configured total is the *input*, taken from the deadline itself:
        a caller that hands in three seconds is owed evidence about three
        seconds, and reporting the module default would misdescribe the bound
        the caller chose.  It is deliberately not re-derived from the remaining
        time, because a 30 000 ms deadline read a hair after it was created has
        29 999 ms left and would misreport the configured total by a
        millisecond.  How much of that total was already gone at entry is
        recorded separately as ``remaining_at_entry_ms``, so neither fact is
        inferred from the other.
        """

        if deadline is None:
            whole = Deadline.after_ms(total_ms, label)
            configured = int(total_ms)
        else:
            whole = deadline
            configured = (
                int(whole.configured_ms)
                if whole.configured_ms is not None
                else int(whole.remaining_seconds * 1000)
            )
        return cls(
            deadline=whole,
            configured_total_ms=configured,
            default_total_ms=int(total_ms),
            caller_supplied_deadline=deadline is not None,
            remaining_at_entry_ms=int(whole.remaining_seconds * 1000),
        )

    @property
    def remaining_ms(self) -> int:
        return int(self.deadline.remaining_seconds * 1000)

    @property
    def exhausted(self) -> bool:
        return self.deadline.expired

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic_ns() - self.started_ns) / 1_000_000)

    def grant(self, stage: str, cap_ms: int) -> Deadline:
        """A capped view of the one deadline.  Never a new budget."""

        granted = self.deadline.sub(cap_ms, stage)
        self._record(stage, int(granted.remaining_seconds * 1000), blocking=True, cap_ms=int(cap_ms))
        return granted

    def grant_seconds(self, stage: str, cap_seconds: float) -> float:
        """The seconds a duration-taking primitive may wait: remaining, capped.

        Zero once the budget is spent, which every such primitive must treat as
        one non-blocking observation rather than as "no limit".
        """

        seconds = min(max(0.0, float(cap_seconds)), self.deadline.remaining_seconds)
        self._record(stage, int(seconds * 1000), blocking=True, cap_ms=int(cap_seconds * 1000))
        return seconds

    def observe(self, stage: str) -> dict[str, Any]:
        """Record a non-blocking step.  It waits for nothing, so it gets nothing."""

        return self._record(stage, 0, blocking=False, cap_ms=0)

    def _record(self, stage: str, granted_ms: int, *, blocking: bool, cap_ms: int) -> dict[str, Any]:
        entry = {
            "stage": stage,
            "granted_ms": granted_ms,
            "stage_maximum_ms": cap_ms,
            "budget_remaining_ms": self.remaining_ms,
            "deadline_expired_at_entry": self.exhausted,
            "blocking": blocking,
        }
        self.grants.append(entry)
        return dict(entry)

    def note(self, stage: str, *, completed: bool) -> None:
        """Record whether a stage finished the thing it claims, or did not."""

        target = self.completed_steps if completed else self.incomplete_steps
        other = self.incomplete_steps if completed else self.completed_steps
        if stage in other:
            other.remove(stage)
        if stage not in target:
            target.append(stage)

    def granted_ms_for(self, stage: str) -> int | None:
        for entry in reversed(self.grants):
            if entry["stage"] == stage:
                return int(entry["granted_ms"])
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured_total_ms": self.configured_total_ms,
            "default_total_ms": self.default_total_ms,
            "caller_supplied_deadline": self.caller_supplied_deadline,
            "remaining_at_entry_ms": self.remaining_at_entry_ms,
            "elapsed_ms": self.elapsed_ms,
            "remaining_ms": self.remaining_ms,
            "deadline_exhausted": self.exhausted,
            "clock": "time.monotonic_ns",
            "renewed_after_a_step": False,
            "stage_grants": [dict(entry) for entry in self.grants],
            "completed_steps": list(self.completed_steps),
            "incomplete_steps": list(self.incomplete_steps),
        }


# --- child-subreaper ownership -----------------------------------------------

PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37

#: Acquisition outcomes.  Exactly one of them permits a fork.
SUBREAPER_APPLIED = "APPLIED"
SUBREAPER_UNAVAILABLE = "UNAVAILABLE_ON_THIS_KERNEL"
#: M2-B37.  The three ways an acquisition can fail to be *established* while the
#: syscall layer still returns.  Each is a refusal, never a held reference.
SUBREAPER_SET_FAILED = "SET_FAILED"
SUBREAPER_READBACK_FAILED = "READBACK_FAILED"
SUBREAPER_READBACK_MISMATCH = "READBACK_MISMATCH"

#: Release outcomes.  Exactly one of them is a restoration.
SUBREAPER_RESTORED = "RESTORED"
#: M2-B39.  A restoration that was requested but not observed, in each of the
#: three ways it can fail to be observed.
SUBREAPER_RESTORE_SET_FAILED = "RESTORE_SET_FAILED"
SUBREAPER_RESTORE_READBACK_FAILED = "RESTORE_READBACK_FAILED"
SUBREAPER_RESTORE_MISMATCH = "RESTORE_MISMATCH"
#: An inner release under an outer acquisition: nothing is restored, and the
#: flag is still required by somebody.
SUBREAPER_REFERENCE_RETAINED = "REFERENCE_RETAINED"
#: A release that released nothing, because the terminal one already happened
#: or none was ever taken.  It never overwrites the terminal result.
SUBREAPER_ALREADY_RELEASED = "ALREADY_RELEASED"
#: The flag is not inherited across ``fork``, so an acquisition object carried
#: into a child describes a flag the child does not hold.  The child discards
#: it; it must never "restore" a process-wide value it never set.
SUBREAPER_INHERITED_DISCARDED = "INHERITED_ACQUISITION_DISCARDED"

#: Acquisition refusals: none of these may be followed by a fork.
SUBREAPER_ACQUISITION_REFUSALS = (
    SUBREAPER_UNAVAILABLE,
    SUBREAPER_SET_FAILED,
    SUBREAPER_READBACK_FAILED,
    SUBREAPER_READBACK_MISMATCH,
)
#: The complete release state machine.
SUBREAPER_RELEASE_RESULTS = (
    SUBREAPER_RESTORED,
    SUBREAPER_RESTORE_SET_FAILED,
    SUBREAPER_RESTORE_READBACK_FAILED,
    SUBREAPER_RESTORE_MISMATCH,
    SUBREAPER_REFERENCE_RETAINED,
    SUBREAPER_ALREADY_RELEASED,
    SUBREAPER_INHERITED_DISCARDED,
)


class ChildSubreaperUnavailable(RuntimeError):
    """The controller could not positively establish subreaper ownership.

    M2-B37.  This is raised *before* anything is created, so a caller that sees
    it knows no descriptor, process, or pidfd exists to clean up and that the
    process-wide flag is exactly as it was.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}:{detail}" if detail else code)
        self.code = code
        self.detail = detail


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
        self._code: str = SUBREAPER_ALREADY_RELEASED
        self._detail: str = "no acquisition has been made"
        self._applied = False
        # M2-B39.  What a restoration intended, what the kernel actually read
        # back, and whether the two agreed.  A restoration is claimed from the
        # readback alone.
        self._restore_intended: int | None = None
        self._restore_observed: int | None = None
        self._restoration_verified = False
        self._cleanup_complete = True
        self._released_nothing = True

    def _reset_after_fork_locked(self) -> None:
        # PR_SET_CHILD_SUBREAPER is not inherited across fork(), so a copy of
        # this object carried into a child describes a flag the child does not
        # have.  It is discarded rather than trusted -- and in particular it is
        # never "restored" by the child, which would write a process-wide value
        # into a process that never set one.
        if self._owner_pid is not None and self._owner_pid != os.getpid():
            self._depth = 0
            self._previous = None
            self._applied = False
            self._owner_pid = None
            self._restore_intended = None
            self._restore_observed = None
            self._restoration_verified = False
            self._cleanup_complete = True
            self._released_nothing = True
            self._code = SUBREAPER_INHERITED_DISCARDED
            self._detail = (
                "the inherited acquisition described another process and was discarded; this "
                "process restored nothing because it never set the flag"
            )

    def _refuse_locked(self, code: str, detail: str, *, rewrite_to: int | None = None) -> None:
        """Fail an acquisition closed: hold nothing, and put the flag back.

        M2-B37.  The caller is about to be told it may not fork.  It must also
        be true that this failed attempt left the process-wide state exactly as
        it found it, so a write that was made and then contradicted is undone
        here and the observed result is recorded rather than assumed.
        """

        residual = None
        if rewrite_to is not None:
            rewrite_error = set_child_subreaper(rewrite_to)
            residual, _ = get_child_subreaper()
            detail = (
                f"{detail}; the previous value {rewrite_to} was rewritten "
                f"(error={rewrite_error}, observed={residual})"
            )
        self._depth = 0
        self._previous = None
        self._owner_pid = None
        self._applied = False
        self._restore_intended = rewrite_to
        self._restore_observed = residual
        self._restoration_verified = rewrite_to is None or residual == rewrite_to
        self._cleanup_complete = self._restoration_verified
        self._released_nothing = True
        self._code = code
        self._detail = detail
        raise ChildSubreaperUnavailable(code, detail)

    def acquire(self) -> dict[str, Any]:
        """Positively establish subreaper ownership, or refuse to hold one.

        M2-B37.  This returns only an acquisition the kernel confirmed.  The
        previous behaviour -- returning a state that said the flag could not be
        set while still counting a reference -- made the ownership guarantee
        optional for a launch path that then proceeded as though it held one.

        :raises ChildSubreaperUnavailable: the flag could not be read, could not
            be set, or does not read back as set.  Nothing is held and the
            process-wide state is left as it was found.
        """

        with self._lock:
            self._reset_after_fork_locked()
            if self._depth > 0 and self._applied:
                # An outer acquisition already proved the kernel state; this one
                # shares that single activation.
                self._depth += 1
                self._code = SUBREAPER_APPLIED
                self._detail = (
                    f"this controller (pid {os.getpid()}) is a child subreaper; {self._depth} "
                    f"trusted helper acquisition(s) share it"
                )
                self._released_nothing = False
                self._cleanup_complete = False
                return self.state()
            previous, read_error = get_child_subreaper()
            if previous is None:
                self._refuse_locked(
                    SUBREAPER_UNAVAILABLE, f"PR_GET_CHILD_SUBREAPER failed: {read_error}"
                )
            write_error = set_child_subreaper(1)
            if write_error is not None:
                self._refuse_locked(
                    SUBREAPER_SET_FAILED, f"PR_SET_CHILD_SUBREAPER(1) failed: {write_error}"
                )
            observed, observe_error = get_child_subreaper()
            if observed is None:
                self._refuse_locked(
                    SUBREAPER_READBACK_FAILED,
                    f"PR_GET_CHILD_SUBREAPER failed after setting 1: {observe_error}",
                    rewrite_to=previous,
                )
            if observed != 1:
                # The write reported success; the kernel disagrees.  That is a
                # claim, not an observation, and it is refused as one.
                self._refuse_locked(
                    SUBREAPER_READBACK_MISMATCH,
                    f"PR_GET_CHILD_SUBREAPER reads {observed} after setting 1",
                    rewrite_to=previous,
                )
            self._previous = previous
            self._applied = True
            self._depth = 1
            self._owner_pid = os.getpid()
            self._code = SUBREAPER_APPLIED
            self._detail = (
                f"this controller (pid {os.getpid()}) is a child subreaper; the previous value "
                f"{previous} is restored when the last trusted helper closes"
            )
            self._restore_intended = None
            self._restore_observed = None
            self._restoration_verified = False
            self._cleanup_complete = False
            self._released_nothing = False
            return self.state()

    def acquire_reference(self) -> "SubreaperReference":
        """Acquire, and hand back a handle that releases exactly once.

        M2-B38.  A caller that is about to fork needs a rollback that cannot
        double-release and cannot be forgotten.  The handle is validated before
        it is returned: an object that does not describe an applied acquisition
        owned by this PID is released and refused rather than carried forward.
        """

        reference = SubreaperReference(self, self.acquire())
        if not reference.valid:
            reference.release()
            raise ChildSubreaperUnavailable(
                SUBREAPER_READBACK_MISMATCH,
                f"the acquisition object does not describe ownership held by pid {os.getpid()}: "
                f"{reference.state}",
            )
        return reference

    def release(self) -> dict[str, Any]:
        """Release one acquisition; restore and *verify* on the last one.

        M2-B39.  ``RESTORED`` is returned only when the kernel reads back
        exactly the value this release intended.  A write that reported success
        while the readback disagrees leaves a truthful residual state, because a
        later consumer that reads RESTORED will assume the process-wide flag is
        back at baseline and act on a flag that is still set.
        """

        with self._lock:
            self._reset_after_fork_locked()
            if self._depth == 0:
                # Nothing is held.  The terminal result of the release that did
                # happen is preserved rather than overwritten by this repeat.
                self._released_nothing = True
                if self._code not in SUBREAPER_RELEASE_RESULTS:
                    self._code = SUBREAPER_ALREADY_RELEASED
                    self._detail = "no acquisition is held; this call released nothing"
                return self.state()
            self._depth -= 1
            self._released_nothing = False
            if self._depth > 0:
                self._code = SUBREAPER_REFERENCE_RETAINED
                self._detail = (
                    f"{self._depth} trusted helper acquisition(s) still hold the flag; nothing was "
                    "restored and nothing is claimed restored"
                )
                return self.state()
            intended = self._previous if self._previous is not None else 0
            set_error = set_child_subreaper(intended)
            observed, read_error = get_child_subreaper()
            if set_error is not None:
                code = SUBREAPER_RESTORE_SET_FAILED
                detail = (
                    f"PR_SET_CHILD_SUBREAPER({intended}) failed: {set_error}; the process-wide "
                    f"flag is not back at baseline (observed {observed})"
                )
            elif observed is None:
                code = SUBREAPER_RESTORE_READBACK_FAILED
                detail = (
                    f"PR_GET_CHILD_SUBREAPER failed after restoring {intended}: {read_error}; the "
                    "restoration was requested and never observed"
                )
            elif observed != intended:
                code = SUBREAPER_RESTORE_MISMATCH
                detail = (
                    f"the child-subreaper flag was set to {intended} and reads {observed}; the "
                    "restoration is not claimed and this process is still a child subreaper"
                )
            else:
                code = SUBREAPER_RESTORED
                detail = (
                    f"the child-subreaper flag was restored to {intended} and the kernel reads "
                    f"{observed}"
                )
            self._code = code
            self._detail = detail
            self._restore_intended = intended
            self._restore_observed = observed
            self._restoration_verified = code == SUBREAPER_RESTORED
            self._cleanup_complete = code == SUBREAPER_RESTORED
            self._applied = False
            # The evidence of what was held survives a failed restoration: it is
            # the only remaining record of what this process still owes.
            self._previous = None if code == SUBREAPER_RESTORED else intended
            return self.state()

    @property
    def active(self) -> bool:
        with self._lock:
            self._reset_after_fork_locked()
            return self._applied and self._depth > 0

    @property
    def cleanup_complete(self) -> bool:
        """Whether this ownership left the process-wide flag at its baseline."""

        with self._lock:
            return self._cleanup_complete

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "code": self._code,
                "detail": self._detail,
                "applied": self._applied,
                "depth": self._depth,
                "previous_value": self._previous,
                "owner_pid": self._owner_pid,
                "restore_intended": self._restore_intended,
                "restore_observed": self._restore_observed,
                "restoration_verified": self._restoration_verified,
                "cleanup_complete": self._cleanup_complete,
                "released_nothing": self._released_nothing,
            }


class SubreaperReference:
    """One acquisition of the process-wide flag, released at most once.

    M2-B38.  The rollback of a failed launch must be exact: releasing twice
    would decrement an acquisition somebody else still needs, and not releasing
    at all would leave the flag set for a helper that was never created.  The
    handle makes both impossible, and repeating the rollback is a no-op that
    reports the first release rather than performing a second.
    """

    def __init__(self, owner: ChildSubreaperOwnership, state: dict[str, Any]) -> None:
        self._owner = owner
        self._state = dict(state)
        self._holder_pid = os.getpid()
        self._released = False
        self._release_state: dict[str, Any] = {}

    @property
    def state(self) -> dict[str, Any]:
        return dict(self._state)

    @property
    def released(self) -> bool:
        return self._released

    @property
    def holder_pid(self) -> int:
        return self._holder_pid

    @property
    def valid(self) -> bool:
        """Whether this handle describes ownership positively held by this PID."""

        return (
            not self._released
            and self._holder_pid == os.getpid()
            and self._state.get("code") == SUBREAPER_APPLIED
            and bool(self._state.get("applied"))
            and int(self._state.get("depth") or 0) > 0
            and self._state.get("owner_pid") == os.getpid()
        )

    def release(self) -> dict[str, Any]:
        """Release this acquisition once.  Idempotent, and never cross-process."""

        if self._released:
            return dict(self._release_state)
        self._released = True
        if self._holder_pid != os.getpid():
            # A handle carried across fork() names a flag this process does not
            # hold.  Releasing it here would restore a process-wide value this
            # process never set.
            self._release_state = {
                "code": SUBREAPER_INHERITED_DISCARDED,
                "detail": (
                    f"the acquisition was taken by pid {self._holder_pid}; pid {os.getpid()} "
                    "discarded it and restored nothing"
                ),
                "applied": False,
                "depth": 0,
                "previous_value": None,
                "owner_pid": self._holder_pid,
                "restore_intended": None,
                "restore_observed": None,
                "restoration_verified": False,
                "cleanup_complete": True,
                "released_nothing": True,
            }
            return dict(self._release_state)
        self._release_state = self._owner.release()
        return dict(self._release_state)


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
        "acquisition_gate": (
            "M2-B37.  Acquisition either returns kernel-confirmed state or raises "
            "ChildSubreaperUnavailable.  No socket, fork, pidfd, helper, or launcher is created "
            "before it succeeds, so the launch path can never proceed on an ownership guarantee "
            "it does not hold."
        ),
        "fork_failure_rollback": (
            "M2-B38.  Every exit path between acquisition and successful ownership transfer "
            "destroys and reaps the partially created child, closes every descriptor, and then "
            "releases the acquisition exactly once through a handle that cannot double-release."
        ),
        "restoration_claim": (
            "M2-B39.  RESTORED is returned only when PR_GET_CHILD_SUBREAPER reads back exactly "
            "the intended value.  RESTORE_SET_FAILED, RESTORE_READBACK_FAILED and "
            "RESTORE_MISMATCH are truthful residual states that keep the intended and observed "
            "values and mark the cleanup incomplete."
        ),
        "release_results": list(SUBREAPER_RELEASE_RESULTS),
        "acquisition_refusals": list(SUBREAPER_ACQUISITION_REFUSALS),
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
    "ChildSubreaperUnavailable",
    "CleanupBudget",
    "ControllerDeadlineExpired",
    "Deadline",
    "HELPER_COOPERATIVE_EXIT_DEADLINE_MS",
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
    "SUBREAPER_ACQUISITION_REFUSALS",
    "SUBREAPER_ALREADY_RELEASED",
    "SUBREAPER_APPLIED",
    "SUBREAPER_INHERITED_DISCARDED",
    "SUBREAPER_READBACK_FAILED",
    "SUBREAPER_READBACK_MISMATCH",
    "SUBREAPER_REFERENCE_RETAINED",
    "SUBREAPER_RELEASE_RESULTS",
    "SUBREAPER_RESTORED",
    "SUBREAPER_RESTORE_DEADLINE_MS",
    "SUBREAPER_RESTORE_MISMATCH",
    "SUBREAPER_RESTORE_READBACK_FAILED",
    "SUBREAPER_RESTORE_SET_FAILED",
    "SUBREAPER_SET_FAILED",
    "SUBREAPER_UNAVAILABLE",
    "SubreaperReference",
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
