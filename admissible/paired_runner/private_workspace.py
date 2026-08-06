"""Private per-effect execution view and trusted transactional export.

A live writable bind of the authorized host workspace cannot satisfy the
governing invariant that the effect process never observes a host-backed IPC
endpoint.  A host-visible temporary directory is also insufficient: a same-UID
host process that discovers its path can plant a FIFO there while the effect
runs.

Every effect therefore materialises its writable view onto a tmpfs that exists
only inside a private user+mount namespace helper (``PRIVATE_MOUNTNS_TMPFS``),
retained solely by an open directory descriptor.  After process-domain
quiescence a trusted controller computes a closed change set and exports it
through a durable, race-safe transactional protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import threading
import time
from typing import Any, Callable, ClassVar, Iterator

from .canonical import Fingerprint, fingerprint, canonical_bytes
from .cgroup_launch import (
    GateReleaseOutcome,
    RELEASE_NOT_RELEASED,
    RELEASE_OUTCOME_UNKNOWN,
    RELEASE_PHASE_ACCEPTED,
    RELEASE_PHASE_ACCEPT_DEADLINE_EXPIRED,
    RELEASE_PHASE_COMPLETION_DEADLINE_EXPIRED,
    RELEASE_PHASE_NOT_GATED,
    RELEASE_PHASE_NOT_REQUESTED,
    RELEASE_PHASE_REQUEST_NOT_SENT,
    RELEASE_PHASE_WRITE_COMPLETED,
    RELEASE_PHASE_WRITE_FAILED,
    RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
    classify_release_frames,
    gate_child_before_exec,
    monotonic_release_truth,
    release_gate,
)
from .process_ownership import (
    ABORT_TOTAL_DEADLINE_MS,
    CHILD_SUBREAPER,
    HELPER_CONTROL_RPC_DEADLINE_MS,
    HELPER_COOPERATIVE_EXIT_DEADLINE_MS,
    HELPER_REAP_DEADLINE_MS,
    HELPER_RELEASE_ACCEPT_DEADLINE_MS,
    HELPER_RELEASE_COMPLETION_DEADLINE_MS,
    HELPER_SHUTDOWN_DEADLINE_MS,
    HELPER_STARTUP_DEADLINE_MS,
    HELPER_WAIT_RPC_MARGIN_MS,
    LAUNCHER_EXIT_OBSERVATION_DEADLINE_MS,
    LAUNCHER_REAP_DEADLINE_MS,
    REAPER_MOUNT_NAMESPACE_HELPER,
    REAPER_NONE,
    REAPER_TRUSTED_CONTROLLER,
    REAP_ALREADY_REAPED,
    REAP_SUBREAPER_UNAVAILABLE,
    SUBREAPER_RESTORE_DEADLINE_MS,
    SUBREAPER_UNSETTLED_RESULTS,
    ChildSubreaperUnavailable,
    CleanupBudget,
    ControllerDeadlineExpired,
    Deadline,
    ProcessOwnershipEvidence,
    ReapOutcome,
    SubreaperReference,
    is_addressable_pid,
    observe_process_exit,
    open_process_descriptor,
    ownership_generation,
    process_is_zombie,
    process_present,
    process_restoration_debt,
    reap_owned_child,
    signal_process,
)
from .resource_limits import (
    _release_unregistered as _release_unregistered_cleanup,
    _retain_unregistered as _retain_unregistered_cleanup,
    cleanup_obligation_sequence_of as _obligation_sequence_of,
    next_cleanup_obligation_sequence as _next_obligation_sequence,
    set_cleanup_registrar as _set_cleanup_registrar,
    unregistered_cleanups as _unregistered_cleanups,
)
from .observation import (
    M2_PREFIX,
    M2_SCHEMA_VERSION,
    ObservationError,
    _decode_fp,
    _decode_strings,
    _encode_fp,
    _encode_strings,
    _M2Record,
    _require_int,
    _require_text,
    m2_schema_descriptor,
)


SCHEMA_SOURCE_SNAPSHOT_IDENTITY = f"{M2_PREFIX}.source_snapshot_identity"
SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY = f"{M2_PREFIX}.private_execution_view_identity"
SCHEMA_PROPOSED_EXPORT_CHANGE_SET = f"{M2_PREFIX}.proposed_export_change_set"
SCHEMA_EXPORT_RESERVATION = f"{M2_PREFIX}.export_reservation"
SCHEMA_EXPORT_RECEIPT = f"{M2_PREFIX}.export_receipt"
SCHEMA_EXPORT_RECONCILIATION = f"{M2_PREFIX}.export_reconciliation"
SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION = f"{M2_PREFIX}.transactional_export_reservation"

EXPORT_OPERATIONS = (
    "CREATE_REGULAR_FILE",
    "UPDATE_REGULAR_FILE",
    "DELETE_REGULAR_FILE",
    "CREATE_DIRECTORY",
    "DELETE_DIRECTORY",
    "CREATE_SYMLINK",
    "UPDATE_SYMLINK",
    "DELETE_SYMLINK",
)

EXPORT_STATES = (
    "RESERVED",
    "APPLIED",
    "REFUSED_SOURCE_MUTATED",
    "REFUSED_UNSUPPORTED_INODE",
    "REFUSED_PARTIAL",
    "REFUSED_CRASH_CLASSIFIABLE",
    "REFUSED_CONCURRENT_MUTATION",
    "REFUSED_AMBIGUOUS",
    "REFUSED_REPLAY",
)

EXPORT_PROTOCOL_VERSION = 1
MAX_EXPORT_ENTRIES = 100_000
MAX_MATERIALIZE_BYTES = 2 * 1024 * 1024 * 1024
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o755
PRIVATE_FILE_MODE = 0o644
MATERIALIZATION_KIND = "PRIVATE_MOUNTNS_TMPFS"
DEFAULT_PRIVATE_TMPFS_SIZE = "2g"

_CLONE_NEWNS = getattr(os, "CLONE_NEWNS", 0x00020000)
_CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_REC = 16384
_MS_PRIVATE = 1 << 18


class PrivateWorkspaceError(RuntimeError):
    """The private view or trusted export cannot proceed."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}:{detail}" if detail else code)
        self.code = code
        self.detail = detail


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _send_framed(sock: socket.socket, payload: dict[str, Any], fds: tuple[int, ...] = ()) -> None:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header = struct.pack("!I", len(raw))
    # Length header travels alone so SCM_RIGHTS always accompanies the JSON body.
    sock.sendall(header)
    if fds:
        sock.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", list(fds)))])
    else:
        sock.sendall(raw)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = sock.recv(size - len(chunks))
        if not piece:
            raise PrivateWorkspaceError("private_mountns_helper_closed", "short_read")
        chunks.extend(piece)
    return bytes(chunks)


def _recv_framed(sock: socket.socket) -> tuple[dict[str, Any], list[int]]:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length > 1 << 20:
        raise PrivateWorkspaceError("private_mountns_frame_too_large", str(length))
    raw, ancillary, _flags, _address = sock.recvmsg(length, socket.CMSG_SPACE(256))
    if len(raw) < length:
        raw += _recv_exact(sock, length - len(raw))
    fds: list[int] = []
    for level, typ, data in ancillary or ():
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            values = array.array("i")
            values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
            fds.extend(int(value) for value in values)
    return json.loads(raw.decode("utf-8")), fds


# --- M2-B33: controller-owned deadlines on the helper protocol ----------------
#
# The helper is a separate process.  Every operation that waits on it therefore
# waits on something that may be alive and silent, stopped, wedged, or
# protocol-deadlocked.  The bound below is enforced by *this* process: the
# socket timeout is derived from an absolute monotonic instant this controller
# owns, is recomputed before each underlying syscall so a sequence of reads
# cannot renew its own budget, and is restored afterwards.
#
# A deadline that expires mid-frame destroys the framing: the controller cannot
# know how many bytes of a length-prefixed message the helper already sent.  The
# connection is therefore marked broken, and every later call on it refuses
# immediately instead of blocking again.  That is what keeps the whole abort
# path bounded rather than bounded-per-call.


class HelperDeadlineExpired(PrivateWorkspaceError):
    """A controller-owned deadline expired waiting for the trusted helper."""

    def __init__(self, operation: str, detail: str = "") -> None:
        super().__init__("private_mountns_helper_deadline", f"{operation}:{detail}" if detail else operation)
        self.operation = operation


class HelperProtocolBroken(PrivateWorkspaceError):
    """The framed protocol lost its boundaries and may never be resumed."""

    def __init__(self, detail: str = "") -> None:
        super().__init__("private_mountns_helper_protocol_broken", detail)


def _arm(sock: socket.socket, deadline: Deadline, operation: str) -> None:
    """Point the socket at the controller's absolute deadline, or refuse now."""

    remaining = deadline.remaining_seconds
    if remaining <= 0.0:
        raise HelperDeadlineExpired(operation, "the controller deadline had already expired")
    sock.settimeout(remaining)


def _send_framed_within(
    sock: socket.socket,
    payload: dict[str, Any],
    fds: tuple[int, ...],
    deadline: Deadline,
    operation: str,
) -> None:
    """Send one frame under a controller-owned deadline.

    A helper that stops reading can fill the socket buffer, so the send is
    bounded too; an unbounded write to a wedged peer is the same defect as an
    unbounded read from one.
    """

    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    previous = sock.gettimeout()
    try:
        _arm(sock, deadline, operation)
        sock.sendall(struct.pack("!I", len(raw)))
        if fds:
            sent = 0
            _arm(sock, deadline, operation)
            sent = sock.sendmsg(
                [raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", list(fds)))]
            )
            while sent < len(raw):
                _arm(sock, deadline, operation)
                sent += sock.send(raw[sent:])
        else:
            _arm(sock, deadline, operation)
            sock.sendall(raw)
    except TimeoutError as error:
        raise HelperDeadlineExpired(operation, f"the request frame was not delivered: {error}") from error
    finally:
        try:
            sock.settimeout(previous)
        except OSError:  # pragma: no cover - the socket is already gone
            pass


def _recv_exact_within(sock: socket.socket, size: int, deadline: Deadline, operation: str) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        _arm(sock, deadline, operation)
        try:
            piece = sock.recv(size - len(chunks))
        except TimeoutError as error:
            raise HelperDeadlineExpired(operation, f"a partial frame stalled: {error}") from error
        if not piece:
            raise PrivateWorkspaceError("private_mountns_helper_closed", "short_read")
        chunks.extend(piece)
    return bytes(chunks)


def _recv_framed_within(
    sock: socket.socket, deadline: Deadline, operation: str
) -> tuple[dict[str, Any], list[int]]:
    """Receive one frame under a controller-owned deadline."""

    previous = sock.gettimeout()
    try:
        header = _recv_exact_within(sock, 4, deadline, operation)
        (length,) = struct.unpack("!I", header)
        if length > 1 << 20:
            raise PrivateWorkspaceError("private_mountns_frame_too_large", str(length))
        _arm(sock, deadline, operation)
        try:
            raw, ancillary, _flags, _address = sock.recvmsg(length, socket.CMSG_SPACE(256))
        except TimeoutError as error:
            raise HelperDeadlineExpired(operation, f"the reply frame did not arrive: {error}") from error
        if not raw and length:
            raise PrivateWorkspaceError("private_mountns_helper_closed", "short_read")
        if len(raw) < length:
            raw += _recv_exact_within(sock, length - len(raw), deadline, operation)
        fds: list[int] = []
        for level, typ, data in ancillary or ():
            if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                values = array.array("i")
                values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
                fds.extend(int(value) for value in values)
        return json.loads(raw.decode("utf-8")), fds
    finally:
        try:
            sock.settimeout(previous)
        except OSError:  # pragma: no cover - the socket is already gone
            pass


def _fork() -> int:
    """The controller's single fork primitive (M2-B37).

    Every trusted process this controller creates passes through here, so
    "acquisition failure never reaches fork()" is a property of one call site
    that a test can assert directly rather than an ordering it has to infer.
    """

    return os.fork()


#: M2-B43.  Failed starts whose forked child could not be reaped inside the
#: rollback's own deadline, and whose acquisition is therefore still held.  The
#: rollback raises, so without somewhere to keep the handle the retry would be
#: unreachable and the only remaining choice would be to release ownership over
#: an unreaped child.  Entries are PID-bound and are removed the moment their
#: reap and their single release both succeed.
_UNSETTLED_FAILED_STARTS: list["_UnsettledFailedStart"] = []


class _UnsettledFailedStart:
    """One partially created helper whose cleanup is incomplete but retryable.

    M2-B46.  A cleanup that reaped its child and called release exactly once has
    done everything it *can* do and not necessarily everything it *owes*: a
    release whose restoration the kernel did not read back leaves the
    process-wide flag away from the baseline this start was responsible for.
    Completion therefore requires four facts, not two -- the exact child reaped,
    the exact reference released once, the restoration positively settled, and
    no process-wide restoration debt standing -- and the entry survives until
    all four hold, because deleting it is deleting the only handle that can
    settle the fourth.
    """

    def __init__(self, *, helper_pid: int, subreaper: SubreaperReference) -> None:
        self.helper_pid = helper_pid
        self.subreaper = subreaper
        self.owner_pid = os.getpid()
        self.reaped = False
        self.reap: ReapOutcome | None = None
        #: Whether the single release has been performed.  Named for what it is:
        #: a release that returned RESTORE_MISMATCH *was* attempted and must
        #: never be attempted again.
        self.released = False
        self.release_state: dict[str, Any] = {}
        #: What the single release actually returned, kept immutably beside
        #: whatever a later settlement changes.
        self.release_result: str | None = None
        #: The activation this failed start's acquisition was cut from, and the
        #: baseline that acquisition owes.
        self.ownership_generation = int(subreaper.generation)
        self.owed_baseline = subreaper.state.get("previous_value")
        self.settlements: list[dict[str, Any]] = []
        self.retries = 0
        self.last_retry: dict[str, Any] = {}
        # M2-B53.  The retry is a lifecycle transition -- reap, release once,
        # settle -- and two callers reaching it together must perform one of
        # each between them, not two.
        self._lock = threading.RLock()

    @property
    def restoration_settled(self) -> bool:
        """Whether this start's release left the process-wide flag settled."""

        if not self.released:
            return False
        if self.release_state.get("code") in SUBREAPER_UNSETTLED_RESULTS:
            return False
        return not bool(self.release_state.get("debt_outstanding"))

    @property
    def debt_outstanding(self) -> bool:
        return process_restoration_debt() is not None

    @property
    def cleanup_complete(self) -> bool:
        return (
            self.reaped
            and self.released
            and self.restoration_settled
            and not self.debt_outstanding
        )

    def _settle_locked(self) -> dict[str, Any]:
        settlement = self.subreaper.settle_restoration_debt()
        self.settlements.append(settlement)
        if settlement.get("settled"):
            # The debt this release left is gone, so the release result stops
            # being the outstanding fact and the settled ownership document
            # replaces it.  Both remain visible: the release code is kept in the
            # evidence beside the settlement that ended it.
            self.release_state = dict(settlement["state"])
        return settlement

    def retry(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """Reap the exact child, release once, then settle what the release owes.

        M2-B53.  Serialised: concurrent retries reap once, release once and
        settle once between them.
        """

        with self._lock:
            return self._retry_locked(deadline=deadline)

    def _retry_locked(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        bound = deadline or Deadline.after_ms(HELPER_REAP_DEADLINE_MS, "failed_start_retry")
        if self.owner_pid != os.getpid():  # pragma: no cover - defensive
            return {
                "helper_pid": self.helper_pid,
                "performed": False,
                "reason": (
                    f"the failed start belongs to pid {self.owner_pid}; pid {os.getpid()} owns "
                    "neither the child nor the acquisition"
                ),
                "helper_reaped": self.reaped,
                "subreaper_released": self.released,
                "cleanup_complete": False,
            }
        self.retries += 1
        if not self.reaped:
            outcome = _kill_and_reap_owned(self.helper_pid, bound)
            self.reap = outcome
            self.reaped = outcome.reaped
        released_here = False
        if self.reaped and not self.released:
            # Reap first, release second.  Never the other way round, and never
            # a second time: `released` records the attempt, not its outcome.
            self.released = True
            released_here = True
            self.release_state = self.subreaper.release()
            self.release_result = self.release_state.get("code")
        settlement: dict[str, Any] = {}
        if self.released and not self.restoration_settled:
            # M2-B46.  The operation that makes this entry terminal.  ``prctl``
            # does not block, so it costs the caller's budget nothing and is
            # attempted on the same call that discovered the debt as well as on
            # every later one.
            settlement = self._settle_locked()
        evidence = {
            "helper_pid": self.helper_pid,
            "performed": True,
            "reason": "",
            "retries": self.retries,
            "helper_reaped": self.reaped,
            "helper_exit_code": None if self.reap is None else self.reap.exit_code,
            "helper_zombie": process_is_zombie(self.helper_pid),
            "helper_present": process_present(self.helper_pid),
            "subreaper_released": self.released,
            "subreaper_released_by_this_call": released_here,
            "subreaper_release_result": self.release_result,
            "subreaper": dict(self.release_state),
            "owed_baseline": self.owed_baseline,
            "ownership_generation": self.ownership_generation,
            "restoration_settled": self.restoration_settled,
            "restoration_settlement": dict(settlement),
            "settlement_attempts": len(self.settlements),
            "debt_outstanding": self.debt_outstanding,
            "cleanup_complete": self.cleanup_complete,
            "cleanup_retryable": not self.cleanup_complete,
            "deadline": bound.to_dict(),
        }
        if self.cleanup_complete and self in _UNSETTLED_FAILED_STARTS:
            # Removed only now: while anything above is false this entry is the
            # only reachable handle to the reap, the release, or the settlement.
            _UNSETTLED_FAILED_STARTS.remove(self)
        evidence["registry_retained"] = self in _UNSETTLED_FAILED_STARTS
        self.last_retry = dict(evidence)
        return evidence


def unsettled_failed_starts() -> tuple["_UnsettledFailedStart", ...]:
    """Failed starts this process has not finished cleaning up (M2-B43)."""

    return tuple(_UNSETTLED_FAILED_STARTS)


def retry_unsettled_failed_starts(*, deadline: Deadline | None = None) -> list[dict[str, Any]]:
    """Retry every incomplete failed-start cleanup with a fresh bounded budget.

    M2-B46.  A retry reaps what is unreaped, releases what is unreleased exactly
    once, and settles the process-wide restoration its own release left owing.
    An entry is removed only when all three are terminal.
    """

    return [pending.retry(deadline=deadline) for pending in tuple(_UNSETTLED_FAILED_STARTS)]


# --- M2-B48: incomplete cleanup outlives the frame that detected it -----------
#
# Every object on the private-execution path could already *return* incomplete
# cleanup evidence.  The production call chain then dropped it: BoundRuntime.
# close() returned evidence into a `finally` that ignored it, _EffectPreparation.
# close() returned None, _execute_permitted_effect() never looked, the execution
# outcome had nowhere to carry it, and PrivateExecutionView.materialize()
# discarded its helper's closure on the exception path.  Once those local
# wrappers left scope the retry handle was unreachable, so an incomplete cleanup
# was retryable only in the sense that nothing could reach the retry.
#
# The registry below is the smallest thing that makes the retry survive: it is
# PID-bound, it retains only incomplete objects, it names each one deterministic-
# ally, it exposes a bounded drain, and it refuses new effects rather than
# growing without limit.

#: How many incomplete cleanups this process will hold before it refuses to
#: start another private execution view.  A registry that grew without limit
#: would convert a leak of processes into a leak of memory; refusing is the
#: fail-closed answer and is disclosed rather than silently capped.
CLEANUP_REGISTRY_CAPACITY = 64

CLEANUP_KIND_HELPER = "PRIVATE_MOUNT_HELPER"
CLEANUP_KIND_VIEW = "PRIVATE_EXECUTION_VIEW"
#: M2-B48.  The third obligation an unfinished effect can leave: a per-effect
#: cgroup whose members outlived the effect, which ``close()`` truthfully
#: refuses to remove and which nothing retained once the supervision frame
#: returned.  Process ownership being settled does not settle this.
CLEANUP_KIND_EFFECT_CGROUP = "EFFECT_CGROUP"

#: What a retryable cleanup would do next.  A cleanup that advertises a retry
#: and cannot name the operation is the defect M2-B47 closes, so the name is
#: derived from the evidence rather than asserted.
CLEANUP_RETRY_REAP = "REAP_THE_EXACT_HELPER_PID"
CLEANUP_RETRY_RELEASE = "RELEASE_THE_ACQUISITION_ONCE"
CLEANUP_RETRY_SETTLE = "SETTLE_THE_PROCESS_WIDE_RESTORATION_DEBT"
#: M2-B48.  The obligation process ownership being settled does not settle.
CLEANUP_RETRY_REMOVE_CGROUP = "REMOVE_THE_EXACT_OWNED_EFFECT_CGROUP"
#: M2-B51.  The obligation an absent cgroup does not discharge.
CLEANUP_RETRY_REAP_OWNED = "REAP_THE_EXACT_OWNED_PROCESSES"
#: M2-B52.  The obligation exists and the registry has not retained it yet.
CLEANUP_RETRY_REGISTER = "REGISTER_THE_UNRESOLVED_OBLIGATION"
CLEANUP_RETRY_NONE = "NOTHING_REMAINS"


def _cleanup_retry_operation(evidence: dict[str, Any]) -> str:
    if evidence.get("cleanup_complete"):
        return CLEANUP_RETRY_NONE
    if not evidence.get("reaped"):
        return CLEANUP_RETRY_REAP
    if evidence.get("ownership_retained"):
        return CLEANUP_RETRY_RELEASE
    return CLEANUP_RETRY_SETTLE


#: The kind a retained handle is, decided by its type rather than guessed.
_CLEANUP_KINDS = {
    "PrivateExecutionView": CLEANUP_KIND_VIEW,
    "PrivateMountHelper": CLEANUP_KIND_HELPER,
    "EffectCgroup": CLEANUP_KIND_EFFECT_CGROUP,
}


class CleanupRegistrySaturated(PrivateWorkspaceError):
    """This process holds as many unresolved cleanups as it will hold."""

    def __init__(self, detail: str = "") -> None:
        super().__init__("cleanup_registry_saturated", detail)


class CleanupRegistrationFailed(PrivateWorkspaceError):
    """An obligation exists and the registry could not be made to retain it."""

    def __init__(self, detail: str = "") -> None:
        super().__init__("cleanup_registration_failed", detail)


# --- M2-B52: capacity is reserved before an obligation may be created ---------
#
# ``require_capacity()`` and ``record()`` were two operations with a whole effect
# between them.  ``require_capacity()`` checked and returned; ``record()`` then
# allocated an id and inserted unconditionally, so the check could pass at 63,
# the effect could run, and the insertion could take the registry to 65 -- or two
# threads could each pass the check at 63 and each insert.  A reservation closes
# the gap: it is taken atomically before anything can create the obligation, it
# is carried through the effect, and it is either converted into exactly one
# entry or given back.

#: How long a whole registry drain may spend, for a caller that supplies no
#: deadline of its own.  M2-B54: this is the total for the *drain*, not a
#: per-entry allowance, so sixty-four entries cost this once.
CLEANUP_DRAIN_TOTAL_DEADLINE_MS = HELPER_SHUTDOWN_DEADLINE_MS

#: M2-B58.  One counter per interpreter, so two registries alive at the same
#: moment can never carry the same identity and a token cannot be presented to
#: the wrong one.
_REGISTRY_SEQUENCE = 0
_REGISTRY_SEQUENCE_LOCK = threading.Lock()

#: M2-B57.  The one budget a drain is currently spending on this thread.  A
#: nested cleanup path that reaches :func:`drain_incomplete_cleanups` again joins
#: it rather than minting a second full budget, which is the same mistake as
#: giving each handle a fresh deadline, one stack frame further down.
_ACTIVE_DRAIN = threading.local()

#: Why an obligation was not attempted.  A drain that ran out of budget says so
#: rather than reporting an attempt that did not happen.
DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED = "SHARED_BUDGET_EXHAUSTED"
#: An alias: another obligation in the same drain owns the same exact resource,
#: and its published canonical result positively proves the resource is gone.
DRAIN_UNATTEMPTED_ALIAS = "THE_CANONICAL_OBLIGATION_FOR_THIS_RESOURCE_WAS_SETTLED"
#: M2-B59.  An alias whose canonical obligation did *not* discharge the resource.
#: It takes no second grant and it is not called discharged either.
DRAIN_UNATTEMPTED_CANONICAL_UNRESOLVED = (
    "THE_CANONICAL_OBLIGATION_FOR_THIS_RESOURCE_DID_NOT_DISCHARGE_IT"
)
#: The resource is gone; only bookkeeping remains, and bookkeeping is not a
#: cleanup primitive and is never run on a spent budget.
DRAIN_UNATTEMPTED_RESOURCE_DISCHARGED = "THE_RESOURCE_IS_ALREADY_DISCHARGED"

# --- M2-B57: exactly one truthful state per obligation, per drain -------------
#
# The delegated qualification refused this closure on a single row: an
# unregistered obligation reported ``attempted=false`` with
# ``SHARED_BUDGET_EXHAUSTED`` and a retry operation naming a cgroup removal,
# while the cgroup it named had already been removed -- by its own ordinary
# ``close()``, before the drain began, under that removal's own exclusion
# boundary.  Nothing had bypassed the budget and no two obligations aliased one
# resource; the *evidence model* was wrong.  A registrar failure made
# ``cleanup_complete`` false, and a false ``cleanup_complete`` was read as "a
# destructive obligation is still outstanding".
#
# A drain row now carries exactly one of these states, and the state is derived
# from what the obligation actually still owes rather than from the budget alone.

#: Settled using a grant from the one shared budget.
DRAIN_STATE_ATTEMPTED = "ATTEMPTED_UNDER_A_GRANT_FROM_THE_SHARED_BUDGET"
#: Genuinely untouched: the resource is still outstanding and there was no time.
DRAIN_STATE_RETAINED_UNATTEMPTED = "RETAINED_UNTOUCHED_BECAUSE_THE_SHARED_BUDGET_WAS_EXHAUSTED"
#: The exact same underlying resource was settled by another obligation here,
#: and that obligation's published result proves it.
DRAIN_STATE_DISCHARGED_BY_CANONICAL = "DISCHARGED_BY_THE_CANONICAL_OBLIGATION_FOR_THE_SAME_RESOURCE"
#: M2-B59.  An alias whose canonical obligation is unresolved, retained,
#: unattempted, claimed elsewhere without a terminal result, or which threw
#: before publishing one.  The resource is still outstanding and nothing here
#: claims otherwise; a second settlement grant is still not spent on it.
DRAIN_STATE_RETAINED_PENDING_CANONICAL = (
    "RETAINED_BECAUSE_THE_CANONICAL_OBLIGATION_FOR_THE_SAME_RESOURCE_DID_NOT_DISCHARGE_IT"
)
#: The resource is discharged on its own evidence; only bookkeeping is owed.
DRAIN_STATE_RESOURCE_DISCHARGED = "RESOURCE_ALREADY_DISCHARGED_BOOKKEEPING_OUTSTANDING"
#: Attempted or reached, and something real is still owed.
DRAIN_STATE_UNRESOLVED = "UNRESOLVED_AND_RETAINED"

DRAIN_STATES = (
    DRAIN_STATE_ATTEMPTED,
    DRAIN_STATE_RETAINED_UNATTEMPTED,
    DRAIN_STATE_DISCHARGED_BY_CANONICAL,
    DRAIN_STATE_RETAINED_PENDING_CANONICAL,
    DRAIN_STATE_RESOURCE_DISCHARGED,
    DRAIN_STATE_UNRESOLVED,
)

#: The states that positively prove the canonical obligation's own resource is
#: no longer outstanding.  Only these may discharge an alias (M2-B59).
DRAIN_STATES_PROVING_DISCHARGE = (
    DRAIN_STATE_ATTEMPTED,
    DRAIN_STATE_RESOURCE_DISCHARGED,
)


class DrainEvidenceContradiction(PrivateWorkspaceError):
    """A drain row would have described a state the resource contradicts."""

    def __init__(self, detail: str = "") -> None:
        super().__init__("drain_evidence_contradiction", detail)


# --- M2-B59: an alias is discharged by a *result*, never by a relationship ----
#
# The drain identified the alias relationship before the canonical obligation
# ran, and the classifier then prioritised ``alias_of`` over everything the
# canonical obligation actually did.  The independently reproduced consequence
# was a false cleanup claim over a resource that was still standing:
#
#     canonical: attempted=true  state=UNRESOLVED_AND_RETAINED  outstanding=true
#     alias:     attempted=false state=DISCHARGED_BY_CANONICAL  outstanding=true
#
# Sharing a resource with an obligation that failed to settle it is not a
# discharge.  Each exact-resource identity group is now an explicit state
# machine: one canonical obligation is selected deterministically, it is
# executed, observed or claimed, exactly one canonical *result* is published,
# and every alias is classified from that exact published result -- or from
# nothing, in which case the alias is truthfully retained.


class _CanonicalResult:
    """The one published outcome of one exact resource's canonical obligation.

    Publication is a separate, explicit step from selection.  A canonical
    obligation that is selected but throws, is claimed by another drain, or
    never reaches a terminal state leaves this object *unpublished*, and an
    unpublished result discharges nothing.
    """

    __slots__ = (
        "attempted",
        "generation",
        "grant_ms",
        "label",
        "published",
        "resource_identity",
        "resource_outstanding",
        "retained",
        "settlement_complete",
        "state",
        "unresolved_reason",
    )

    def __init__(self, *, resource_identity: str, label: str, generation: int) -> None:
        self.resource_identity = resource_identity
        self.label = label
        self.generation = generation
        self.published = False
        self.attempted = False
        self.grant_ms = 0
        self.settlement_complete = False
        self.resource_outstanding = True
        self.retained = True
        self.state: str | None = None
        self.unresolved_reason: str | None = None

    def publish(self, row: dict[str, Any]) -> None:
        """Adopt the canonical obligation's own finished row as the result."""

        self.attempted = bool(row["attempted"])
        self.grant_ms = int(row["granted_ms"])
        self.settlement_complete = bool(row["cleanup_complete"])
        self.resource_outstanding = bool(row["resource_outstanding"])
        self.retained = bool(row["retained"])
        self.state = row["state"]
        self.published = True

    def unresolved(self, reason: str) -> None:
        """Record why no result exists.  Nothing is published (M2-B59)."""

        self.published = False
        self.unresolved_reason = reason

    def proves_discharge_of(self, resource_identity: str) -> bool:
        """Whether this result positively proves *that exact* resource is gone."""

        if not self.published:
            return False
        if self.resource_identity != resource_identity:
            return False
        if self.resource_outstanding:
            return False
        if self.state not in DRAIN_STATES_PROVING_DISCHARGE:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_label": self.label,
            "resource_identity": self.resource_identity,
            "publication_generation": self.generation,
            "published": self.published,
            "attempted": self.attempted,
            "granted_ms": self.grant_ms,
            "settlement_complete": self.settlement_complete,
            "resource_outstanding": self.resource_outstanding,
            "retained": self.retained,
            "state": self.state,
            "unresolved_reason": self.unresolved_reason,
            "proves_discharge": self.proves_discharge_of(self.resource_identity),
        }


#: Why a canonical obligation published no result.  Each is a distinct, real
#: way for the state machine to end without proof, and none of them discharges.
CANONICAL_UNPUBLISHED_THREW = "THE_CANONICAL_OBLIGATION_RAISED_BEFORE_PUBLICATION"
CANONICAL_UNPUBLISHED_CLAIMED = "THE_CANONICAL_OBLIGATION_IS_CLAIMED_BY_ANOTHER_DRAIN"
CANONICAL_UNPUBLISHED_NOT_REACHED = "THE_CANONICAL_OBLIGATION_WAS_NOT_REACHED"

#: Every terminal canonical result this process has published, by exact resource
#: identity, with one monotonic publication generation.  A drain whose own
#: canonical obligation was claimed by another drain reads the terminal result
#: that drain published here; without one, nothing is discharged.  PID-bound
#: like every other process-wide fact: a forked child inherits this memory and
#: owns none of the resources the identities were read from.
_CANONICAL_RESULTS: dict[str, _CanonicalResult] = {}
_CANONICAL_RESULT_LOCK = threading.Lock()
_CANONICAL_RESULT_GENERATION = 0
_CANONICAL_RESULT_PID = os.getpid()

#: How many terminal canonical results this process retains.  The table is a
#: convenience for a drain whose canonical obligation another drain owns, not a
#: ledger, so it is bounded for the same reason the cleanup registry is: an
#: unbounded process-wide dictionary turns a long-lived controller into a slow
#: memory leak.  Eviction is fail-closed by construction -- an evicted result can
#: only make a later alias *less* likely to be called discharged, never more --
#: and the oldest publication is the one that goes.
CANONICAL_RESULT_RETENTION = CLEANUP_REGISTRY_CAPACITY * 4


def _reset_canonical_results_locked() -> None:
    global _CANONICAL_RESULT_GENERATION, _CANONICAL_RESULT_PID
    if _CANONICAL_RESULT_PID != os.getpid():
        _CANONICAL_RESULT_PID = os.getpid()
        _CANONICAL_RESULT_GENERATION = 0
        _CANONICAL_RESULTS.clear()


def _next_canonical_generation() -> int:
    global _CANONICAL_RESULT_GENERATION
    with _CANONICAL_RESULT_LOCK:
        _reset_canonical_results_locked()
        _CANONICAL_RESULT_GENERATION += 1
        return _CANONICAL_RESULT_GENERATION


def _publish_canonical_result(result: _CanonicalResult) -> None:
    """Make a terminal canonical result readable by every other drain."""

    if not result.published:  # pragma: no cover - publication is the caller's gate
        return
    with _CANONICAL_RESULT_LOCK:
        _reset_canonical_results_locked()
        existing = _CANONICAL_RESULTS.get(result.resource_identity)
        if existing is not None and existing.generation > result.generation:
            return
        _CANONICAL_RESULTS[result.resource_identity] = result
        while len(_CANONICAL_RESULTS) > CANONICAL_RESULT_RETENTION:
            oldest = min(_CANONICAL_RESULTS, key=lambda key: _CANONICAL_RESULTS[key].generation)
            del _CANONICAL_RESULTS[oldest]


def _published_canonical_result(resource_identity: str) -> _CanonicalResult | None:
    """A published result that positively proves *that exact* resource is gone."""

    with _CANONICAL_RESULT_LOCK:
        _reset_canonical_results_locked()
        result = _CANONICAL_RESULTS.get(resource_identity)
    if result is None or not result.proves_discharge_of(resource_identity):
        return None
    return result


def published_canonical_results() -> dict[str, dict[str, Any]]:
    """Every terminal canonical result this process has published (M2-B59)."""

    with _CANONICAL_RESULT_LOCK:
        _reset_canonical_results_locked()
        return {identity: row.to_dict() for identity, row in _CANONICAL_RESULTS.items()}


def _resource_outstanding(cleanup: dict[str, Any]) -> bool:
    """Whether this obligation still owes work on a real resource.

    Bookkeeping is not a resource.  An obligation whose cgroup is gone and whose
    owned processes are all accounted for owes nothing destructive, however the
    registrar behaved, and may never be reported as an unattempted removal.
    """

    if "resource_outstanding" in cleanup:
        return bool(cleanup["resource_outstanding"])
    # A handle that predates the field -- a helper or a view -- is outstanding
    # exactly while its own cleanup is incomplete.
    return not bool(cleanup.get("cleanup_complete"))


def _classify_drain_row(
    *,
    attempted: bool,
    cleanup: dict[str, Any],
    alias_of: str | None,
    canonical_result: _CanonicalResult | None = None,
    resource_identity: str | None = None,
) -> tuple[str, str | None]:
    """The one truthful state of this obligation in this drain, and its reason.

    ``RETAINED_UNTOUCHED_BECAUSE_THE_SHARED_BUDGET_WAS_EXHAUSTED`` is reserved
    for an obligation whose resource really is still outstanding.  An obligation
    whose resource is gone is never described that way, whatever the budget did.

    M2-B59.  An alias is classified from the *published canonical result* for its
    own exact resource identity, never from the alias relationship.  Without a
    result that positively proves the exact shared resource is no longer
    outstanding, the alias is retained and says which canonical obligation it is
    waiting on -- it is not called discharged, and it still spends no grant.
    """

    outstanding = _resource_outstanding(cleanup)
    if alias_of is not None:
        if (
            resource_identity is not None
            and canonical_result is not None
            and canonical_result.proves_discharge_of(resource_identity)
            and not outstanding
        ):
            return DRAIN_STATE_DISCHARGED_BY_CANONICAL, DRAIN_UNATTEMPTED_ALIAS
        return (
            DRAIN_STATE_RETAINED_PENDING_CANONICAL,
            DRAIN_UNATTEMPTED_CANONICAL_UNRESOLVED,
        )
    if attempted:
        if bool(cleanup.get("cleanup_complete")):
            return DRAIN_STATE_ATTEMPTED, None
        return DRAIN_STATE_UNRESOLVED, None
    if not outstanding:
        return DRAIN_STATE_RESOURCE_DISCHARGED, DRAIN_UNATTEMPTED_RESOURCE_DISCHARGED
    return DRAIN_STATE_RETAINED_UNATTEMPTED, DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED


def _guard_drain_row(
    row: dict[str, Any], *, canonical_result: _CanonicalResult | None = None
) -> dict[str, Any]:
    """Refuse to emit a row whose own fields contradict each other.

    The invariant the previous closure was refused on, enforced where the row is
    built rather than only where it is read: an obligation may not be reported as
    untouched-for-lack-of-budget unless its resource really is still outstanding.

    M2-B59 adds the discharge shapes.  ``DISCHARGED_BY_CANONICAL`` over a
    resource that is still outstanding is the exact false cleanup claim the
    independent audit reproduced, and it is refused here rather than emitted and
    contradicted downstream.  So is a discharge naming a canonical result that is
    missing, unpublished, for a different exact resource identity, or which
    itself reports the resource as outstanding.
    """

    state = row["state"]
    if state not in DRAIN_STATES:  # pragma: no cover - the table above is closed
        raise DrainEvidenceContradiction(f"unknown drain state {state!r}")
    if state == DRAIN_STATE_RETAINED_UNATTEMPTED and not row["resource_outstanding"]:
        raise DrainEvidenceContradiction(
            f"{row.get('effect_cgroup_path')!r} was reported untouched for lack of budget while "
            "its resource is already discharged"
        )
    if state == DRAIN_STATE_ATTEMPTED and not row["attempted"]:  # pragma: no cover - defensive
        raise DrainEvidenceContradiction("an unattempted obligation was reported as attempted")
    if state == DRAIN_STATE_DISCHARGED_BY_CANONICAL:
        identity = row.get("resource_identity")
        if row["resource_outstanding"]:
            raise DrainEvidenceContradiction(
                f"{row.get('effect_cgroup_path')!r} was reported discharged by the canonical "
                f"obligation {row.get('alias_of')!r} while its own resource is still outstanding"
            )
        if canonical_result is None or not canonical_result.published:
            raise DrainEvidenceContradiction(
                f"{row.get('effect_cgroup_path')!r} was reported discharged by a canonical "
                "obligation that published no result"
            )
        if identity is None or not canonical_result.proves_discharge_of(identity):
            raise DrainEvidenceContradiction(
                f"{row.get('effect_cgroup_path')!r} was reported discharged by the canonical "
                f"result of {canonical_result.resource_identity!r}, which does not prove the "
                f"discharge of {identity!r} (state {canonical_result.state!r}, outstanding "
                f"{canonical_result.resource_outstanding!r})"
            )
    if state == DRAIN_STATE_RETAINED_PENDING_CANONICAL:
        if row["alias_of"] is None:  # pragma: no cover - defensive
            raise DrainEvidenceContradiction(
                "an obligation with no canonical obligation was reported as waiting on one"
            )
        if row["attempted"] or row["granted_ms"]:  # pragma: no cover - defensive
            raise DrainEvidenceContradiction(
                "an alias waiting on its canonical obligation spent a second settlement grant"
            )
    return row


# --- M2-B58: a reservation is a linear, registry-issued capability ------------
#
# ``reservation is not None and reservation.active`` was the whole validity test.
# It proved nothing about *whose* capacity the token represented: a token issued
# by another registry instance, a token whose registry had since been PID-reset,
# a token already spent, and a plain object with an ``active`` attribute were all
# accepted, and each of them skipped the capacity check the reservation existed
# to have already passed.  A stale token surviving a PID-bound reset was enough
# to put a second entry into a registry whose capacity was one.
#
# A reservation now carries its whole provenance -- issuing registry object and
# identity, owner PID, registry epoch, id -- and the registry additionally
# proves that the exact object it is being handed is the exact object standing
# in its own reservation table under that id.  That last check is what makes the
# capability unforgeable: a token nobody issued is in no table, and a token the
# registry issued and has since taken back is no longer in it either.

#: The token holds capacity and has not been spent.
RESERVATION_RESERVED = "RESERVED"
#: The token became exactly one cleanup entry.
RESERVATION_CONSUMED = "CONSUMED"
#: The token gave its capacity back without becoming an entry.
RESERVATION_RELEASED = "RELEASED"

#: Why a reservation was refused.  Each is a separate fact, never a single
#: "invalid": a stale token and a forged one are different failures.
RESERVATION_REFUSED_FOREIGN_TYPE = "RESERVATION_IS_NOT_A_REGISTRY_ISSUED_CAPABILITY"
RESERVATION_REFUSED_FOREIGN_REGISTRY = "RESERVATION_WAS_ISSUED_BY_ANOTHER_REGISTRY"
RESERVATION_REFUSED_FOREIGN_PID = "RESERVATION_BELONGS_TO_ANOTHER_PROCESS"
RESERVATION_REFUSED_STALE_EPOCH = "RESERVATION_PREDATES_THE_CURRENT_REGISTRY_EPOCH"
RESERVATION_REFUSED_NOT_IN_TABLE = "RESERVATION_ID_IS_NOT_OUTSTANDING"
RESERVATION_REFUSED_NOT_THE_SAME_OBJECT = "RESERVATION_ID_STANDS_FOR_A_DIFFERENT_OBJECT"
RESERVATION_REFUSED_ALREADY_CONSUMED = "RESERVATION_WAS_ALREADY_CONSUMED"
RESERVATION_REFUSED_ALREADY_RELEASED = "RESERVATION_WAS_ALREADY_RELEASED"


class CleanupReservationRefused(PrivateWorkspaceError):
    """A reservation could not be proved to be this registry's live capability."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__("cleanup_reservation_refused", f"{code}:{detail}" if detail else code)
        self.code = code


class _CapacityReservation:
    """One unit of registry capacity, held before the obligation exists.

    Linear: it becomes exactly one cleanup entry or it is given back, once.  It
    carries the identity of the registry that issued it, the PID that owned that
    registry, and the epoch the registry was in, and it exposes no method that
    could make any of them say something else.
    """

    __slots__ = (
        "_registry",
        "_state",
        "converted_to",
        "epoch",
        "label",
        "owner_pid",
        "registry_identity",
        "reservation_id",
    )

    def __init__(
        self,
        registry: "_IncompleteCleanupRegistry",
        reservation_id: str,
        label: str,
        *,
        registry_identity: str,
        epoch: int,
    ) -> None:
        self._registry = registry
        self.reservation_id = reservation_id
        self.label = label
        self.owner_pid = os.getpid()
        self.registry_identity = registry_identity
        self.epoch = int(epoch)
        self._state = RESERVATION_RESERVED
        self.converted_to: str | None = None

    @property
    def state(self) -> str:
        return self._state

    @property
    def active(self) -> bool:
        """Whether this token still holds capacity.

        Read-only.  A settable ``active`` was a public method for making a spent
        or foreign token look current, which is precisely what a linear
        capability may not have.
        """

        return self._state == RESERVATION_RESERVED

    def release(self) -> bool:
        """Give the capacity back.  Idempotent, and never releases twice.

        Returns ``False`` when this token holds nothing to give back, including
        when the registry that issued it no longer recognises it -- a token that
        outlived a PID reset releases nothing and takes nothing away from the
        registry now standing in its place.
        """

        return self._registry._release_reservation(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "label": self.label,
            "owner_pid": self.owner_pid,
            "registry_identity": self.registry_identity,
            "epoch": self.epoch,
            "state": self._state,
            "active": self.active,
            "converted_to": self.converted_to,
        }


class _IncompleteCleanup:
    """One retained handle to a cleanup this process has not finished."""

    def __init__(
        self,
        entry_id: str,
        kind: str,
        handle: Any,
        evidence: dict[str, Any],
        *,
        generation: int = 0,
        sequence: int = 0,
    ) -> None:
        self.entry_id = entry_id
        self.kind = kind
        self.handle = handle
        #: M2-B57.  Where this obligation sits in the one process-wide order a
        #: drain spends its single budget in.
        self.sequence = int(sequence) or _next_obligation_sequence()
        self.owner_pid = os.getpid()
        self.helper_pid = int(evidence.get("helper_pid") or 0)
        self.registered_generation = int(evidence.get("ownership_generation") or 0)
        #: M2-B53.  The registry generation this entry was inserted under.  A
        #: drain that finishes settling an entry may only publish or remove the
        #: entry it claimed, never whatever now stands under the same id.
        self.generation = int(generation)
        #: M2-B53.  Whether a drain currently owns this entry.  Two drains may
        #: not settle one handle at the same time.
        self.claimed_by: int | None = None
        #: M2-B48.  The exact cgroup this entry owes a removal for, when it owes
        #: one.  It is the containment path this controller created, never a
        #: workspace or repository path, and it is retained because a removal
        #: that cannot name its target cannot be retried.
        self.effect_path = evidence.get("effect_path")
        self.owned_identity = evidence.get("owned_identity")
        self.cleanup = dict(evidence)
        self.drains = 0

    @property
    def terminal(self) -> bool:
        return bool(self.cleanup.get("cleanup_complete"))

    def retry(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """Retry the exact operation this entry retains, boundedly.

        Every retained handle answers one protocol -- ``settle_cleanup`` -- so a
        drain discharges a helper, a view and a cgroup obligation the same way
        and cannot silently skip a kind it does not recognise.
        """

        self.drains += 1
        self.handle.settle_cleanup(deadline=deadline)
        self.cleanup = dict(self.handle.cleanup_evidence())
        return dict(self.cleanup)

    def evidence(self) -> dict[str, Any]:
        """What this entry retains.  No workspace or repository path is in it."""

        return {
            "entry_id": self.entry_id,
            "kind": self.kind,
            "sequence": self.sequence,
            "owner_pid": self.owner_pid,
            "helper_pid": self.helper_pid,
            "ownership_generation": self.registered_generation,
            "registry_generation": self.generation,
            "claimed": self.claimed_by is not None,
            "effect_cgroup_path": self.cleanup.get("effect_path"),
            "owned_identity": self.cleanup.get("owned_identity"),
            "drain_attempts": self.drains,
            "cleanup_complete": bool(self.cleanup.get("cleanup_complete")),
            "cleanup_retryable": bool(self.cleanup.get("cleanup_retryable")),
            "cleanup_retry_operation": self.cleanup.get("cleanup_retry_operation"),
            "containment_settled": bool(self.cleanup.get("containment_settled")),
            "process_obligations_complete": bool(
                self.cleanup.get("process_obligations_complete", True)
            ),
            "unresolved_owned_processes": list(
                self.cleanup.get("unresolved_owned_processes") or ()
            ),
            "reaped": bool(self.cleanup.get("reaped")),
            "ownership_retained": bool(self.cleanup.get("ownership_retained")),
            "restoration_settled": bool(self.cleanup.get("restoration_settled")),
            "debt_outstanding": bool(self.cleanup.get("debt_outstanding")),
            "settlement_attempts": int(self.cleanup.get("settlement_attempts") or 0),
        }


class _IncompleteCleanupRegistry:
    """The process-level owner of every unresolved private-execution cleanup.

    PID-bound by construction: a ``fork`` child inherits this module's memory but
    owns none of the processes, descriptors, or acquisitions the entries
    describe, so it discards them rather than retrying a parent's cleanup.

    M2-B52.  One lock covers every transition: the fork check, the capacity
    arithmetic, the id allocation, the insertion, the removal, the evidence
    snapshot, the drain claim, and the fork reset.  It is never held across a
    blocking settlement -- a drain claims under the lock, settles outside it, and
    reacquires it to publish -- so a slow helper shutdown cannot stall an
    unrelated registration.
    """

    def __init__(self) -> None:
        global _REGISTRY_SEQUENCE
        self._lock = threading.RLock()
        self._owner_pid = os.getpid()
        self._entries: dict[str, _IncompleteCleanup] = {}
        self._reservations: dict[str, _CapacityReservation] = {}
        self._counter = 0
        self._reservation_counter = 0
        self._generation = 0
        # M2-B58.  The immutable identity of this exact registry object, and the
        # PID-bound epoch a reservation is valid within.  The identity separates
        # two registries alive at once; the epoch separates this registry from
        # what it was before a fork reset it.  Neither is derived from anything a
        # token can carry, so a token can only match by having been issued here.
        with _REGISTRY_SEQUENCE_LOCK:
            _REGISTRY_SEQUENCE += 1
            self._identity = f"cleanup-registry-{os.getpid()}-{_REGISTRY_SEQUENCE:06d}"
        self._epoch = 1
        self._reservation_refusals: list[dict[str, Any]] = []

    # --- state, always under the one lock -------------------------------------

    def _reset_after_fork_locked(self) -> None:
        if self._owner_pid != os.getpid():
            self._owner_pid = os.getpid()
            self._entries = {}
            self._reservations = {}
            self._counter = 0
            self._reservation_counter = 0
            self._generation = 0
            # M2-B58.  The epoch advances rather than resetting: a token the
            # parent issued names the epoch it was issued in, and the child must
            # never be able to reach an epoch a parent's token could match.
            self._epoch += 1
            self._reservation_refusals = []

    @property
    def registry_identity(self) -> str:
        return self._identity

    @property
    def epoch(self) -> int:
        with self._lock:
            self._reset_after_fork_locked()
            return self._epoch

    def reservation_refusals(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._reservation_refusals)

    # --- M2-B58: proving a token is this registry's live capability ------------

    def _classify_reservation_locked(self, token: Any) -> str | None:
        """``None`` when the token is this registry's live capability.

        Every element of the provenance is checked separately and none of them
        is inferred from another.  The last two are what make the capability
        unforgeable: the id must be outstanding *in this registry's own table*,
        and the object standing under it must be this exact object.
        """

        if not isinstance(token, _CapacityReservation):
            return RESERVATION_REFUSED_FOREIGN_TYPE
        if token._registry is not self or token.registry_identity != self._identity:
            return RESERVATION_REFUSED_FOREIGN_REGISTRY
        if token.owner_pid != os.getpid():
            return RESERVATION_REFUSED_FOREIGN_PID
        if token.epoch != self._epoch:
            return RESERVATION_REFUSED_STALE_EPOCH
        if token.state == RESERVATION_CONSUMED:
            return RESERVATION_REFUSED_ALREADY_CONSUMED
        if token.state == RESERVATION_RELEASED:
            return RESERVATION_REFUSED_ALREADY_RELEASED
        outstanding = self._reservations.get(token.reservation_id)
        if outstanding is None:
            return RESERVATION_REFUSED_NOT_IN_TABLE
        if outstanding is not token:
            return RESERVATION_REFUSED_NOT_THE_SAME_OBJECT
        return None

    def _refuse_reservation_locked(self, token: Any, code: str, operation: str) -> dict[str, Any]:
        """Record a classified refusal.  The refused token is not touched."""

        record = {
            "operation": operation,
            "code": code,
            "registry_identity": self._identity,
            "registry_epoch": self._epoch,
            "reading_pid": os.getpid(),
            "token_type": type(token).__name__,
            "token_reservation_id": getattr(token, "reservation_id", None),
            "token_registry_identity": getattr(token, "registry_identity", None),
            "token_owner_pid": getattr(token, "owner_pid", None),
            "token_epoch": getattr(token, "epoch", None),
            "token_state": getattr(token, "state", None),
            "held": self._held_locked(),
            "capacity": CLEANUP_REGISTRY_CAPACITY,
        }
        self._reservation_refusals.append(record)
        return record

    def _reset_after_fork(self) -> None:
        with self._lock:
            self._reset_after_fork_locked()

    def _held_locked(self) -> int:
        """Combined reservations and retained entries.  Never one without the other."""

        return len(self._entries) + len(self._reservations)

    @property
    def owner_pid(self) -> int:
        with self._lock:
            self._reset_after_fork_locked()
            return self._owner_pid

    def saturated(self) -> bool:
        with self._lock:
            self._reset_after_fork_locked()
            return self._held_locked() >= CLEANUP_REGISTRY_CAPACITY

    def _saturation_detail(self) -> str:
        return (
            f"pid {os.getpid()} holds {len(self._entries)} unresolved private-execution "
            f"cleanups and {len(self._reservations)} outstanding reservations, which is the "
            f"capacity of {CLEANUP_REGISTRY_CAPACITY}; no further obligation is created until "
            "they are drained"
        )

    def reserve(self, label: str = "") -> _CapacityReservation:
        """Take one unit of capacity atomically, or refuse fail-closed.

        The reservation is what makes "refuse before the effect" true rather than
        hoped for: it is held from before the fork or the ``mkdir`` until the
        obligation is either registered or positively completed.
        """

        with self._lock:
            self._reset_after_fork_locked()
            if self._held_locked() >= CLEANUP_REGISTRY_CAPACITY:
                raise CleanupRegistrySaturated(self._saturation_detail())
            self._reservation_counter += 1
            reservation_id = (
                f"reservation-{self._owner_pid}-{self._epoch}-{self._reservation_counter:06d}"
            )
            reservation = _CapacityReservation(
                self,
                reservation_id,
                label,
                registry_identity=self._identity,
                epoch=self._epoch,
            )
            self._reservations[reservation_id] = reservation
            return reservation

    def _release_reservation(self, reservation: Any) -> bool:
        """Give one unit of capacity back, if this token actually holds one.

        M2-B58.  The provenance is proved first.  A foreign, stale or already
        spent token releases nothing, is not mutated, and cannot take capacity
        away from a registry that never issued it.
        """

        with self._lock:
            self._reset_after_fork_locked()
            refusal = self._classify_reservation_locked(reservation)
            if refusal is not None:
                self._refuse_reservation_locked(reservation, refusal, "release")
                return False
            reservation._state = RESERVATION_RELEASED
            self._reservations.pop(reservation.reservation_id, None)
            return True

    def _consume_reservation_locked(self, reservation: Any, entry_id: str) -> None:
        """The one atomic transition: outstanding reservation -> one entry."""

        self._reservations.pop(reservation.reservation_id, None)
        reservation._state = RESERVATION_CONSUMED
        reservation.converted_to = entry_id

    def _restore_reservation_locked(self, reservation: _CapacityReservation) -> None:
        """Undo a consumption whose insertion did not complete."""

        reservation._state = RESERVATION_RESERVED
        reservation.converted_to = None
        self._reservations[reservation.reservation_id] = reservation

    def outstanding_reservations(self) -> tuple[_CapacityReservation, ...]:
        with self._lock:
            self._reset_after_fork_locked()
            return tuple(self._reservations.values())

    def require_capacity(self) -> None:
        """Refuse a new private execution view fail-closed at capacity.

        Retained for callers that only need the refusal; :meth:`reserve` is what
        a caller that is about to create an obligation must use, because a check
        that does not hold the capacity it checked for holds nothing.
        """

        with self._lock:
            self._reset_after_fork_locked()
            if self._held_locked() >= CLEANUP_REGISTRY_CAPACITY:
                raise CleanupRegistrySaturated(self._saturation_detail())

    def record(
        self,
        handle: Any,
        evidence: dict[str, Any],
        *,
        reservation: _CapacityReservation | None = None,
    ) -> str | None:
        """Retain an incomplete cleanup, or release a completed one.

        Registration is driven by the evidence rather than by the caller, so a
        completed cleanup is never registered and an incomplete one is retained
        wherever it is detected.

        M2-B52.  Insertion consumes the reservation the obligation was created
        under.  An insertion with no reservation still has to fit inside the
        capacity in its own right, so a direct call can never take the registry
        past its bound.

        M2-B60.  "Inside the capacity" is the *combined* count -- retained
        entries plus live reservations -- because that is the quantity the bound
        is stated over and the quantity every other gate here enforces.  A
        reservation-less insertion that only counted entries could take the
        registry past its bound whenever any capacity was committed to an
        outstanding reservation.

        M2-B58.  The reservation is proved to be *this* registry's live,
        outstanding, unspent capability before it grants anything.  A token that
        cannot be proved is refused before the insertion, is not mutated, and
        takes nothing from the registry's own accounting; the refusal is
        classified and recorded.
        """

        with self._lock:
            self._reset_after_fork_locked()
            existing = getattr(handle, "_registry_id", None)
            if evidence.get("cleanup_complete"):
                if existing is not None:
                    self._entries.pop(existing, None)
                    handle._registry_id = None
                self._settle_spent_reservation_locked(reservation, None, "record_complete")
                return None
            if existing is not None and existing in self._entries:
                self._entries[existing].cleanup = dict(evidence)
                # The obligation is already retained under one entry; the
                # reservation it was created under is spent on that entry.
                self._settle_spent_reservation_locked(reservation, existing, "record_existing")
                return existing
            reserved = False
            if reservation is not None:
                refusal = self._classify_reservation_locked(reservation)
                if refusal is not None:
                    record = self._refuse_reservation_locked(reservation, refusal, "record")
                    raise CleanupReservationRefused(
                        refusal,
                        (
                            f"{self._identity} epoch {self._epoch} pid {os.getpid()} holds "
                            f"{record['held']} of {CLEANUP_REGISTRY_CAPACITY}; the reservation "
                            f"offered ({record['token_reservation_id']!r} from "
                            f"{record['token_registry_identity']!r}, owner pid "
                            f"{record['token_owner_pid']!r}, epoch {record['token_epoch']!r}, "
                            f"state {record['token_state']!r}) is not this registry's live "
                            "capability, so it grants no capacity and no entry is inserted"
                        ),
                    )
                reserved = True
            if reservation is None and self._held_locked() >= CLEANUP_REGISTRY_CAPACITY:
                # M2-B60.  Held capacity is entries *and* live reservations --
                # that is what ``reserve()``, ``saturated()`` and
                # ``require_capacity()`` have always meant by it -- so a
                # reservation-less insertion is bounded by the same combined
                # count.  Checking ``len(self._entries)`` alone let a direct
                # ``record()`` walk past a registry whose whole capacity was
                # already committed to outstanding reservations: at capacity one,
                # one reservation and one direct insertion produced held=2.  The
                # refusal happens here, inside the one critical section and
                # before the counter, the generation, the entry, the handle or
                # the token is touched, so nothing is mutated by a refusal.
                raise CleanupRegistrySaturated(self._saturation_detail())
            kind = _CLEANUP_KINDS.get(type(handle).__name__, CLEANUP_KIND_HELPER)
            self._counter += 1
            self._generation += 1
            entry_id = f"cleanup-{self._owner_pid}-{self._counter:06d}"
            if reserved:
                # One atomic transition, entirely under the one lock: the exact
                # reservation leaves the table, exactly one entry takes its
                # place, and the token is marked spent.  If the entry cannot be
                # constructed the reservation goes back, so the capacity it held
                # is never lost to a half-finished conversion.
                self._consume_reservation_locked(reservation, entry_id)
            try:
                self._entries[entry_id] = _IncompleteCleanup(
                    entry_id,
                    kind,
                    handle,
                    evidence,
                    generation=self._generation,
                    sequence=_obligation_sequence_of(handle),
                )
            except Exception:
                self._entries.pop(entry_id, None)
                if reserved:
                    self._restore_reservation_locked(reservation)
                raise
            handle._registry_id = entry_id
            return entry_id

    def _settle_spent_reservation_locked(
        self, reservation: Any, entry_id: str | None, operation: str
    ) -> None:
        """Give back a token that is not going to become a *new* entry.

        A token this registry cannot prove is left exactly as it is: refusing to
        release a foreign reservation and refusing to mutate it are the same
        requirement, because a registry that "released" somebody else's token
        would be reporting an accounting change it did not make.
        """

        if reservation is None:
            return
        refusal = self._classify_reservation_locked(reservation)
        if refusal is not None:
            if refusal not in (
                RESERVATION_REFUSED_ALREADY_CONSUMED,
                RESERVATION_REFUSED_ALREADY_RELEASED,
            ):
                # An already-spent token of this registry's own is the ordinary
                # repeated-registration case and is not a refusal worth
                # recording; anything else is.
                self._refuse_reservation_locked(reservation, refusal, operation)
            return
        if entry_id is not None:
            reservation.converted_to = entry_id
        reservation._state = RESERVATION_RELEASED
        self._reservations.pop(reservation.reservation_id, None)

    def entry(self, entry_id: str) -> _IncompleteCleanup | None:
        with self._lock:
            self._reset_after_fork_locked()
            return self._entries.get(entry_id)

    def entries(self) -> tuple[_IncompleteCleanup, ...]:
        with self._lock:
            self._reset_after_fork_locked()
            return tuple(self._entries.values())

    def evidence(self) -> dict[str, Any]:
        with self._lock:
            self._reset_after_fork_locked()
            return {
                "owner_pid": self._owner_pid,
                "reading_pid": os.getpid(),
                "registry_identity": self._identity,
                "epoch": self._epoch,
                "capacity": CLEANUP_REGISTRY_CAPACITY,
                "retained": len(self._entries),
                "reserved": len(self._reservations),
                "held": self._held_locked(),
                "saturated": self._held_locked() >= CLEANUP_REGISTRY_CAPACITY,
                "reservations": [row.to_dict() for row in self._reservations.values()],
                "reservation_refusals": [dict(row) for row in self._reservation_refusals],
                "entries": [entry.evidence() for entry in self._entries.values()],
            }

    # --- M2-B53/M2-B54: one claim per entry, one deadline per drain -----------

    def _claim_locked(self, entry: _IncompleteCleanup, token: int) -> bool:
        if entry.claimed_by is not None:
            return False
        if self._entries.get(entry.entry_id) is not entry:
            return False
        entry.claimed_by = token
        return True

    def pending(self) -> tuple[_IncompleteCleanup, ...]:
        """The retained entries, in the one process-wide obligation order."""

        with self._lock:
            self._reset_after_fork_locked()
            return tuple(sorted(self._entries.values(), key=lambda entry: entry.sequence))

    def drain_entry(
        self,
        entry: _IncompleteCleanup,
        *,
        budget: CleanupBudget,
        token: int,
        alias_of: str | None = None,
        canonical_result: _CanonicalResult | None = None,
        resource_identity: str | None = None,
    ) -> dict[str, Any] | None:
        """Settle one claimed entry out of the caller's shared budget.

        ``None`` means another drain owns the entry: it is neither settled twice
        nor reported as this drain's work.

        M2-B53.  The claim is taken under the registry lock, the settlement
        happens outside it, and the result is published only if the entry claimed
        is still the entry registered.

        M2-B57.  The budget belongs to the caller.  This method never opens one,
        so an entry can never receive a fresh full deadline of its own, and the
        *grant itself* is the gate: an obligation that receives no time runs no
        cleanup primitive at all, rather than running one against an instant that
        has already passed.

        M2-B59.  ``canonical_result`` is the published outcome of the canonical
        obligation for ``resource_identity``.  It is what an alias row is
        classified from; the alias relationship on its own discharges nothing.
        """

        with self._lock:
            if not self._claim_locked(entry, token):
                return None
        stage = f"drain:{entry.entry_id}"
        try:
            granted, granted_ms, attempted = _grant_or_observe(budget, stage, alias_of=alias_of)
            if attempted:
                cleanup = entry.retry(deadline=granted)
            else:
                cleanup = dict(entry.cleanup)
            budget.note(stage, completed=bool(cleanup.get("cleanup_complete")))
        finally:
            with self._lock:
                entry.claimed_by = None
        with self._lock:
            still_registered = self._entries.get(entry.entry_id) is entry
        state, reason = _classify_drain_row(
            attempted=attempted,
            cleanup=cleanup,
            alias_of=alias_of,
            canonical_result=canonical_result,
            resource_identity=resource_identity,
        )
        return _guard_drain_row(
            {
                "entry_id": entry.entry_id,
                "collection": "REGISTERED",
                "sequence": entry.sequence,
                "kind": entry.kind,
                "helper_pid": entry.helper_pid,
                "drain_attempts": entry.drains,
                "attempted": attempted,
                "state": state,
                "unattempted_reason": reason,
                "alias_of": alias_of,
                "canonical_result": None if canonical_result is None else canonical_result.to_dict(),
                "resource_outstanding": _resource_outstanding(cleanup),
                "outstanding_work": cleanup.get("outstanding_work"),
                "resource_identity": cleanup.get("owned_identity"),
                "granted_ms": granted_ms,
                "deadline_exhausted": budget.exhausted,
                "cleanup_complete": bool(cleanup.get("cleanup_complete")),
                "cleanup_retryable": bool(cleanup.get("cleanup_retryable")),
                "cleanup_retry_operation": cleanup.get("cleanup_retry_operation"),
                "effect_cgroup_path": cleanup.get("effect_path"),
                "retained": still_registered,
                "removed": not still_registered,
            },
            canonical_result=canonical_result,
        )

    def drain(
        self, *, deadline: Deadline | None = None, budget: CleanupBudget | None = None
    ) -> list[dict[str, Any]]:
        """Retry every retained cleanup once, inside one absolute deadline.

        M2-B54.  The whole drain spends one instant.  Every claimed entry
        receives only what is left of it, capped by the per-entry maximum, so
        sixty-four entries cost the configured total once rather than
        sixty-four times.  Once nothing remains, the remaining entries are
        reported with non-blocking evidence and are retained unattempted; they
        are not given a fresh budget and are not silently dropped.

        M2-B57.  ``budget`` is the caller's whole budget when the caller has one.
        A registry drain reached from :func:`drain_incomplete_cleanups` shares
        that object with the unregistered collection, so the two can never spend
        the configured total twice between them.  Only a caller that owns no
        budget -- a direct sweep of the registry alone -- opens one here, and it
        opens exactly one.
        """

        if budget is None:
            budget = CleanupBudget.open(
                deadline, total_ms=CLEANUP_DRAIN_TOTAL_DEADLINE_MS, label="cleanup_drain"
            )
            owns_ledger = True
        else:
            owns_ledger = False
        token = threading.get_ident()
        results: list[dict[str, Any]] = []
        for entry in self.pending():
            row = self.drain_entry(entry, budget=budget, token=token)
            if row is not None:
                results.append(row)
        if owns_ledger:
            self._last_drain = budget.to_dict()
        return results

    def last_drain_budget(self) -> dict[str, Any]:
        """The ledger of the most recent drain, for durable evidence (M2-B54)."""

        return dict(getattr(self, "_last_drain", {}) or {})

    def publish_drain_ledger(self, ledger: dict[str, Any]) -> None:
        """Adopt the shared ledger of a drain that covered both collections."""

        self._last_drain = dict(ledger)


_CLEANUP_REGISTRY = _IncompleteCleanupRegistry()

#: M2-B57.  The one ledger of the most recent whole drain, covering the
#: registered entries and the registrar-refused obligations together.
_LAST_DRAIN_LEDGER: dict[str, Any] = {}


def _record_cleanup(
    handle: Any, evidence: dict[str, Any], *, reservation: Any | None = None
) -> str | None:
    """The registrar the containment layer calls, resolved at call time.

    A function rather than a bound method: the registry object is the process's,
    and a caller that replaced it must not find an old one still being written
    to through a captured reference.
    """

    return _CLEANUP_REGISTRY.record(handle, evidence, reservation=reservation)


def _reserve_cleanup_capacity(label: str = "") -> _CapacityReservation:
    """The reserver the containment layer calls before it creates a cgroup."""

    return _CLEANUP_REGISTRY.reserve(label)


# M2-B48.  The containment layer discovers unremoved per-effect cgroups and this
# layer owns the process registry that keeps them reachable.  The dependency is
# a hook rather than an import so containment keeps no knowledge of private
# execution, and installing it here means every unresolved removal in this
# process is retained wherever it is discovered.
#
# M2-B52.  The reserver travels the same way and for the same reason: capacity
# must be taken before the containment layer creates the directory that would
# become an obligation this process could not retain.
_set_cleanup_registrar(_record_cleanup, reserver=_reserve_cleanup_capacity)


def incomplete_cleanups() -> tuple[_IncompleteCleanup, ...]:
    """Every unresolved private-execution cleanup this process still owns."""

    return _CLEANUP_REGISTRY.entries()


def cleanup_registry_evidence() -> dict[str, Any]:
    """The registry's durable evidence.  It names no filesystem path."""

    evidence = _CLEANUP_REGISTRY.evidence()
    unregistered = _unregistered_cleanups()
    evidence["unregistered_obligations"] = len(unregistered)
    evidence["unregistered_obligation_sequences"] = [
        _obligation_sequence_of(handle) for handle in unregistered
    ]
    # M2-B57.  One ledger over both collections, not one per collection.
    evidence["last_drain"] = dict(_LAST_DRAIN_LEDGER) or _CLEANUP_REGISTRY.last_drain_budget()
    return evidence


def _grant_or_observe(
    budget: CleanupBudget, stage: str, *, alias_of: str | None = None
) -> tuple[Deadline | None, int, bool]:
    """Take a grant from the one shared budget, or take nothing and do nothing.

    M2-B57.  The *grant* is the gate, not a check taken just before it.  A
    settlement handed an instant that has already passed still runs every
    non-blocking step it owns -- it kills, it reaps, it removes -- so "the budget
    was exhausted" and "no cleanup primitive ran" were two different facts, and a
    zero-millisecond grant was enough to perform a real destructive removal.  A
    grant that carries no time is therefore no grant at all: nothing is settled,
    and the obligation is retained exactly as it was found.

    An alias never takes a second grant: the resource it names is being settled
    once, by its canonical obligation.
    """

    if alias_of is not None:
        budget.observe(stage)
        return None, 0, False
    if budget.exhausted:
        budget.observe(stage)
        return None, 0, False
    granted = budget.grant(stage, HELPER_SHUTDOWN_DEADLINE_MS)
    granted_ms = int(granted.remaining_seconds * 1000)
    if granted_ms <= 0 or granted.expired:
        # The budget ran out between the check and the grant.  A settlement
        # cannot be given zero time and still be called an attempt.
        return None, 0, False
    return granted, granted_ms, True


def _drain_unregistered_obligation(
    handle: Any,
    *,
    budget: CleanupBudget,
    sequence: int,
    alias_of: str | None = None,
    canonical_result: _CanonicalResult | None = None,
    resource_identity: str | None = None,
) -> dict[str, Any]:
    """Settle one registrar-refused obligation out of the shared budget.

    M2-B57.  It receives a *grant* -- what is left of the one drain budget,
    capped by the per-obligation maximum -- and never a deadline of its own.
    Without a grant it is not attempted at all: it is retained exactly as it was,
    no cleanup primitive runs, and the row says which of the truthful states it
    is in.  In particular an obligation whose resource is already discharged is
    never reported as an untouched, outstanding removal.
    """

    stage = f"drain:unregistered:{sequence}"
    granted, granted_ms, attempted = _grant_or_observe(budget, stage, alias_of=alias_of)
    settlement: dict[str, Any] | None = None
    if attempted:
        settlement = handle.settle_cleanup(deadline=granted)
    cleanup = handle.cleanup_evidence()
    budget.note(stage, completed=bool(cleanup.get("cleanup_complete")))
    state, reason = _classify_drain_row(
        attempted=attempted,
        cleanup=cleanup,
        alias_of=alias_of,
        canonical_result=canonical_result,
        resource_identity=resource_identity,
    )
    return _guard_drain_row(
        {
            "entry_id": None,
            "collection": "UNREGISTERED",
            "sequence": sequence,
            "kind": _CLEANUP_KINDS.get(type(handle).__name__, CLEANUP_KIND_HELPER),
            "helper_pid": int(cleanup.get("helper_pid") or 0),
            "drain_attempts": int(cleanup.get("settlement_attempts") or 0),
            "attempted": attempted,
            "state": state,
            "unattempted_reason": reason,
            "alias_of": alias_of,
            "canonical_result": None if canonical_result is None else canonical_result.to_dict(),
            "resource_outstanding": _resource_outstanding(cleanup),
            "outstanding_work": cleanup.get("outstanding_work"),
            "resource_identity": cleanup.get("owned_identity"),
            "granted_ms": granted_ms,
            "deadline_exhausted": budget.exhausted,
            "cleanup_complete": bool(cleanup.get("cleanup_complete")),
            "cleanup_retryable": bool(cleanup.get("cleanup_retryable")),
            "cleanup_retry_operation": cleanup.get("cleanup_retry_operation"),
            "effect_cgroup_path": cleanup.get("effect_path"),
            "registration_failure": cleanup.get("registration_failure"),
            "retained": any(existing is handle for existing in _unregistered_cleanups()),
            "removed": False,
            "settlement": settlement,
        },
        canonical_result=canonical_result,
    )


def drain_incomplete_cleanups(*, deadline: Deadline | None = None) -> list[dict[str, Any]]:
    """Retry every retained incomplete cleanup within one bounded budget.

    M2-B52.  Obligations whose registration the registrar refused are retried
    here too: they are the ones with no entry to be found by, so a drain that
    only walked the registry would leave exactly the handles that were hardest
    to reach.

    M2-B57.  One call has exactly one absolute budget, and that one budget covers
    the registered entries, the registry bookkeeping the drain needs, the
    obligations retained after a registrar failure, and every retry and evidence
    operation any of them performs.  It is created here, at the outermost entry,
    and nothing below may create another: the registry adopts it, each obligation
    receives a grant from it, and a nested drain reached from inside a settlement
    joins it rather than minting a second one.

    The two collections are walked as one list in ascending obligation sequence
    -- the order in which this process took the obligations on -- so exhaustion
    propagates across both in whichever order they were actually incurred, and
    neither collection is systematically served first.
    """

    outer = getattr(_ACTIVE_DRAIN, "budget", None)
    if outer is not None:
        # A nested drain.  It spends what is left of the budget already running
        # on this thread; converting a grant back into a full budget is the same
        # defect one frame deeper.
        return _drain_within(outer, publish=False)
    budget = CleanupBudget.open(
        deadline, total_ms=CLEANUP_DRAIN_TOTAL_DEADLINE_MS, label="cleanup_drain"
    )
    _ACTIVE_DRAIN.budget = budget
    try:
        return _drain_within(budget, publish=True)
    finally:
        _ACTIVE_DRAIN.budget = None


def _resource_identity_of(obligation: Any, collection: str) -> str | None:
    """The exact resource an obligation names, or ``None`` when it cannot prove one.

    M2-B57.  The *identity* of the owned object -- its ``dev:ino`` -- never its
    pathname.  Two obligations under one pathname may be two different cgroups,
    and two handles for one cgroup may disagree about the name it is reachable
    by.  An obligation that cannot prove an exact identity is never treated as
    an alias of anything: it is drained on its own terms and retained.
    """

    handle = obligation.handle if collection == "REGISTERED" else obligation
    try:
        identity = handle.cleanup_evidence().get("owned_identity")
    except Exception:  # pragma: no cover - a handle whose evidence refuses
        return None
    return identity if isinstance(identity, str) and identity else None


def _drain_within(budget: CleanupBudget, *, publish: bool) -> list[dict[str, Any]]:
    global _LAST_DRAIN_LEDGER
    token = threading.get_ident()
    work: list[tuple[int, str, Any]] = [
        (entry.sequence, "REGISTERED", entry) for entry in _CLEANUP_REGISTRY.pending()
    ]
    work.extend(
        (_obligation_sequence_of(handle), "UNREGISTERED", handle)
        for handle in _unregistered_cleanups()
    )
    work.sort(key=lambda row: (row[0], row[1]))
    # M2-B57.  One underlying resource is settled once and spends one grant.  The
    # first obligation in the deterministic order that names an exact identity is
    # that resource's canonical obligation; any later obligation naming the same
    # exact identity is its alias and takes no second grant.  Identity is proved,
    # never guessed from a pathname.
    #
    # M2-B59.  Selecting the canonical obligation is where the shared resource is
    # *settled*, not where an alias is *discharged*.  Each exact-resource identity
    # is walked as an explicit state machine -- select, execute or claim, publish
    # exactly one result, then classify the aliases from that exact result -- so a
    # canonical obligation that leaves the resource standing leaves its aliases
    # truthfully retained rather than silently reported as cleaned up.
    canonical: dict[str, str] = {}
    canonical_results: dict[str, _CanonicalResult] = {}
    seen_objects: dict[int, str] = {}
    results: list[dict[str, Any]] = []

    def _settle(
        collection: str,
        obligation: Any,
        sequence: int,
        *,
        alias_of: str | None,
        canonical_result: _CanonicalResult | None,
        identity: str | None,
    ) -> dict[str, Any] | None:
        if collection == "REGISTERED":
            return _CLEANUP_REGISTRY.drain_entry(
                obligation,
                budget=budget,
                token=token,
                alias_of=alias_of,
                canonical_result=canonical_result,
                resource_identity=identity,
            )
        return _drain_unregistered_obligation(
            obligation,
            budget=budget,
            sequence=sequence,
            alias_of=alias_of,
            canonical_result=canonical_result,
            resource_identity=identity,
        )

    for sequence, collection, obligation in work:
        identity = _resource_identity_of(obligation, collection)
        alias_of: str | None = None
        label = f"{collection}:{sequence}"
        result: _CanonicalResult | None = None
        if identity is not None:
            handle = obligation.handle if collection == "REGISTERED" else obligation
            if id(handle) in seen_objects:
                alias_of = seen_objects[id(handle)]
            elif identity in canonical:
                alias_of = canonical[identity]
            else:
                canonical[identity] = label
                seen_objects[id(handle)] = label
                result = _CanonicalResult(
                    resource_identity=identity,
                    label=label,
                    generation=_next_canonical_generation(),
                )
                canonical_results[identity] = result
            if alias_of is not None:
                # The alias is classified from the canonical *result*.  This
                # drain's own result is preferred; a terminal result another
                # drain published for the exact same resource identity is the
                # only other thing that may discharge it, and a resource with no
                # published result at all discharges nothing.
                result = canonical_results.get(identity)
                if result is None or not result.published:
                    published = _published_canonical_result(identity)
                    if published is not None:
                        result = published
                    elif result is None:
                        result = _CanonicalResult(
                            resource_identity=identity,
                            label=alias_of,
                            generation=_next_canonical_generation(),
                        )
                        result.unresolved(CANONICAL_UNPUBLISHED_NOT_REACHED)
        if alias_of is None and result is not None:
            # The canonical obligation for this exact resource.  It is executed
            # first, and its result is published before any alias of it is
            # classified; a raise before publication publishes nothing.
            try:
                row = _settle(
                    collection,
                    obligation,
                    sequence,
                    alias_of=None,
                    canonical_result=None,
                    identity=identity,
                )
            except BaseException:
                result.unresolved(CANONICAL_UNPUBLISHED_THREW)
                raise
            if row is None:
                # Another drain owns it and this one saw no terminal result.
                result.unresolved(CANONICAL_UNPUBLISHED_CLAIMED)
                continue
            result.publish(row)
            _publish_canonical_result(result)
            row["canonical_result"] = result.to_dict()
        else:
            row = _settle(
                collection,
                obligation,
                sequence,
                alias_of=alias_of,
                canonical_result=result,
                identity=identity,
            )
            if row is None:
                continue
        row["label"] = label
        row["canonical_for_resource"] = alias_of is None and identity is not None
        results.append(row)
    if publish:
        ledger = budget.to_dict()
        ledger["collections"] = {
            "REGISTERED": sum(1 for row in results if row["collection"] == "REGISTERED"),
            "UNREGISTERED": sum(1 for row in results if row["collection"] == "UNREGISTERED"),
        }
        ledger["obligations_attempted"] = sum(1 for row in results if row["attempted"])
        ledger["obligations_unattempted"] = sum(1 for row in results if not row["attempted"])
        ledger["obligations_retained"] = sum(1 for row in results if row["retained"])
        ledger["states"] = {
            state: sum(1 for row in results if row["state"] == state)
            for state in DRAIN_STATES
            if any(row["state"] == state for row in results)
        }
        # M2-B59.  An alias that was *reported discharged* and an alias that was
        # merely *found to be an alias* are two different counts, and reporting
        # the second under the first is exactly the false cleanup claim this
        # closure removes.
        ledger["aliases_discharged_by_a_canonical_obligation"] = sum(
            1 for row in results if row["state"] == DRAIN_STATE_DISCHARGED_BY_CANONICAL
        )
        ledger["aliases_retained_pending_canonical"] = sum(
            1 for row in results if row["state"] == DRAIN_STATE_RETAINED_PENDING_CANONICAL
        )
        ledger["aliases_identified"] = sum(1 for row in results if row["alias_of"] is not None)
        ledger["distinct_resources"] = len(
            {row["resource_identity"] for row in results if row["resource_identity"]}
        )
        ledger["canonical_results"] = [
            result.to_dict() for _identity, result in sorted(canonical_results.items())
        ]
        ledger["order"] = [
            {
                "sequence": row["sequence"],
                "collection": row["collection"],
                "state": row["state"],
                "resource_outstanding": row["resource_outstanding"],
                "alias_of": row["alias_of"],
                "canonical_proved_discharge": bool(
                    (row.get("canonical_result") or {}).get("proves_discharge")
                ),
            }
            for row in results
        ]
        ledger["ordering"] = "ascending process-wide cleanup obligation sequence"
        _LAST_DRAIN_LEDGER = ledger
        _CLEANUP_REGISTRY.publish_drain_ledger(ledger)
    return results


def cleanup_drain_ledger() -> dict[str, Any]:
    """The one ledger of the most recent whole drain (M2-B57).

    It covers both collections: what the configured total was, how much of it was
    spent, every grant, which obligations were attempted, which were left
    unattempted because the shared budget was exhausted, and which remain
    retained.
    """

    return dict(_LAST_DRAIN_LEDGER)


def _roll_back_failed_start(
    *,
    pid: int | None,
    sockets: tuple[Any, ...],
    descriptors: tuple[int, ...],
    subreaper: SubreaperReference,
) -> dict[str, Any]:
    """Undo a partially created helper exactly once (M2-B38, M2-B43).

    The order is not incidental.  The forked child is destroyed and reaped
    *first*, because releasing the subreaper acquisition while an orphan of this
    controller is still alive would restore the flag that gives this process the
    right to reap it.  Descriptors are closed next, and the acquisition is
    released last -- through the handle, so a repeated rollback releases
    nothing a second time.

    M2-B43.  If that reap does not happen, the release does not happen either.
    A child this controller forked and could not reap is exactly the case where
    ownership must be retained, so the rollback keeps the acquisition, records
    the cleanup as incomplete, and leaves a retryable entry behind rather than
    restoring a flag it still needs.
    """

    evidence: dict[str, Any] = {
        "helper_pid": pid,
        "helper_forked": pid is not None,
        "helper_reaped": False,
        "helper_exit_code": None,
        "launcher_created": False,
        "sockets_closed": 0,
        "descriptors_closed": 0,
        "subreaper": {},
    }
    owned_child = pid is not None and is_addressable_pid(pid)
    if owned_child:
        outcome = _kill_and_reap_owned(
            pid, Deadline.after_ms(HELPER_REAP_DEADLINE_MS, "helper_startup_reap")
        )
        evidence["helper_reaped"] = outcome.reaped
        evidence["helper_exit_code"] = outcome.exit_code
        evidence["helper_reap_code"] = outcome.code
    for sock in sockets:
        if sock is None:
            continue
        try:
            sock.close()
            evidence["sockets_closed"] = int(evidence["sockets_closed"]) + 1
        except OSError:  # pragma: no cover - already closed
            pass
    for descriptor in descriptors:
        try:
            os.close(descriptor)
            evidence["descriptors_closed"] = int(evidence["descriptors_closed"]) + 1
        except OSError:  # pragma: no cover - already closed
            pass
    if owned_child and not evidence["helper_reaped"]:
        pending = _UnsettledFailedStart(helper_pid=int(pid), subreaper=subreaper)
        _UNSETTLED_FAILED_STARTS.append(pending)
        evidence["subreaper"] = dict(subreaper.state)
        evidence["subreaper_released"] = False
        evidence["ownership_retained"] = True
        evidence["cleanup_complete"] = False
        evidence["cleanup_retryable"] = True
        evidence["restoration_settled"] = False
        evidence["debt_outstanding"] = process_restoration_debt() is not None
        return evidence
    # Nothing was forked, the pid never named a process this controller owns, or
    # the child is positively reaped.  Only now may the acquisition end.
    release_state = subreaper.release()
    evidence["subreaper"] = dict(release_state)
    evidence["subreaper_released"] = True
    evidence["ownership_retained"] = False
    unsettled = (
        release_state.get("code") in SUBREAPER_UNSETTLED_RESULTS
        or bool(release_state.get("debt_outstanding"))
        or process_restoration_debt() is not None
    )
    evidence["restoration_settled"] = not unsettled
    evidence["debt_outstanding"] = process_restoration_debt() is not None
    if unsettled:
        # M2-B46.  The child is reaped and the reference is spent, and the
        # process-wide flag is still not back at the baseline this start owes.
        # That is an incomplete cleanup with exactly one remaining operation, so
        # the entry that can perform it is retained rather than the rollback
        # reporting a completion nobody performed.
        pending = _UnsettledFailedStart(
            helper_pid=int(pid) if owned_child else 0, subreaper=subreaper
        )
        pending.reaped = bool(evidence["helper_reaped"]) or not owned_child
        pending.released = True
        pending.release_state = dict(release_state)
        pending.release_result = release_state.get("code")
        _UNSETTLED_FAILED_STARTS.append(pending)
        evidence["cleanup_complete"] = False
        evidence["cleanup_retryable"] = True
        return evidence
    evidence["cleanup_complete"] = True
    evidence["cleanup_retryable"] = False
    return evidence


def _helper_main(sock: socket.socket, *, size: str) -> None:  # pragma: no cover - child process
    """Mount-namespace helper: private tmpfs + gated launcher spawn service."""

    try:
        try:
            os.unshare(_CLONE_NEWUSER | _CLONE_NEWNS)
        except OSError as error:
            sock.sendall(f"UNSHARE:{error.errno}".encode())
            os._exit(2)
        # Signal the parent to write uid/gid maps (unprivileged userns rule:
        # the mapping writer must be outside the new user namespace).
        sock.sendall(b"READY")
        if sock.recv(4) != b"MAPS":
            os._exit(3)
        libc = _libc()
        libc.mount(b"none", b"/", None, _MS_REC | _MS_PRIVATE, None)
        staging = f"/tmp/.admissible-private-view-{os.getpid()}"
        os.makedirs(staging, mode=PRIVATE_DIR_MODE, exist_ok=True)
        options = f"mode=0755,size={size}".encode()
        if libc.mount(b"tmpfs", staging.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV, options) != 0:
            sock.sendall(f"MNT:{ctypes.get_errno()}".encode())
            os._exit(4)
        handle = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        sock.sendmsg(
            [b"OKFD" + staging.encode("utf-8")],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [handle]))],
        )
        os.close(handle)
        children: dict[int, dict[str, Any]] = {}
        reaped: dict[int, int] = {}
        while True:
            request, received_fds = _recv_framed(sock)
            op = request.get("op")
            if op == "exit":
                for meta in list(children.values()):
                    try:
                        os.kill(meta["pid"], signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        os.waitpid(meta["pid"], 0)
                    except OSError:
                        pass
                _send_framed(sock, {"ok": True})
                os._exit(0)
            if op == "spawn":
                argv = [str(item) for item in request["argv"]]
                parent_fds = [int(item) for item in request["parent_fds"]]
                if len(parent_fds) != len(received_fds):
                    _send_framed(sock, {"ok": False, "error": "fd_count_mismatch"})
                    for handle_fd in received_fds:
                        os.close(handle_fd)
                    continue
                remap = {old: new for old, new in zip(parent_fds, received_fds)}
                rewritten: list[str] = []
                for item in argv:
                    if item.isdigit() and int(item) in remap:
                        rewritten.append(str(remap[int(item)]))
                    elif item.startswith("/proc/self/fd/"):
                        old = int(item.rsplit("/", 1)[1])
                        rewritten.append(f"/proc/self/fd/{remap.get(old, old)}")
                    else:
                        rewritten.append(item)
                for index, item in enumerate(rewritten):
                    if item == "--bind-fd" and index + 2 < len(rewritten):
                        rewritten[index] = "--bind"
                        rewritten[index + 1] = staging
                        break
                await_release = bool(request.get("await_release"))
                gate_r, gate_w = os.pipe()
                stdout_r, stdout_w = os.pipe()
                stderr_r, stderr_w = os.pipe()
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(gate_w)
                        os.close(stdout_r)
                        os.close(stderr_r)
                        os.dup2(stdout_w, 1)
                        os.dup2(stderr_w, 2)
                        os.close(stdout_w)
                        os.close(stderr_w)
                        # stdin from /dev/null
                        null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                        os.dup2(null, 0)
                        os.close(null)
                        keep = set(received_fds) | {0, 1, 2, gate_r}
                        for fd in range(3, 256):
                            if fd not in keep:
                                try:
                                    os.close(fd)
                                except OSError:
                                    pass
                        if await_release:
                            gate_child_before_exec(gate_r)
                        else:
                            os.close(gate_r)
                        os.execv(rewritten[0], rewritten)
                    except BaseException:
                        os._exit(127)
                os.close(gate_r)
                os.close(stdout_w)
                os.close(stderr_w)
                for handle_fd in received_fds:
                    try:
                        os.close(handle_fd)
                    except OSError:
                        pass
                children[pid] = {"pid": pid, "gate_w": gate_w if await_release else -1}
                if not await_release:
                    try:
                        os.close(gate_w)
                    except OSError:
                        pass
                _send_framed(sock, {"ok": True, "pid": pid, "await_release": await_release}, (stdout_r, stderr_r))
                os.close(stdout_r)
                os.close(stderr_r)
                continue
            if op == "release":
                # M2-B30.  The gate write is bracketed by two acknowledgements
                # so the controller can tell "the write was never attempted"
                # from "the write completed but the answer was lost".  The
                # accept frame is deliberately sent *before* the write.
                fault = str(request.get("fault") or "")
                meta = children.get(int(request["pid"]))
                if meta is None:
                    _send_framed(
                        sock,
                        {
                            "phase": RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
                            "ok": False,
                            "released": False,
                            "error": "unknown_pid",
                        },
                    )
                    continue
                gate_w = meta.get("gate_w", -1)
                if gate_w < 0:
                    _send_framed(
                        sock,
                        {
                            "phase": RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
                            "ok": False,
                            "released": False,
                            "error": "no_gate",
                        },
                    )
                    continue
                _send_framed(
                    sock,
                    {"phase": RELEASE_PHASE_ACCEPTED, "ok": True, "released": False},
                )
                if fault == "die_before_write":
                    # Trusted fault seam: the helper dies with the gate still
                    # shut.  The controller must report an unknown outcome, not
                    # "no instruction executed" -- it cannot see which side of
                    # the write the helper died on.
                    os._exit(70)
                try:
                    release_gate(gate_w)
                except OSError as error:
                    meta["gate_w"] = -1
                    _send_framed(
                        sock,
                        {
                            "phase": RELEASE_PHASE_WRITE_FAILED,
                            "ok": False,
                            "released": False,
                            "error": str(error.errno),
                        },
                    )
                    continue
                meta["gate_w"] = -1
                if fault == "die_after_write":
                    # The gate is open and the acknowledgement never arrives.
                    os._exit(71)
                _send_framed(
                    sock,
                    {"phase": RELEASE_PHASE_WRITE_COMPLETED, "ok": True, "released": True},
                )
                continue
            if op == "poll":
                pid = int(request["pid"])
                if pid in reaped:
                    _send_framed(sock, {"ok": True, "returncode": reaped[pid]})
                    continue
                meta = children.get(pid)
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                result = os.waitpid(meta["pid"], os.WNOHANG)
                if result[0] == 0:
                    _send_framed(sock, {"ok": True, "returncode": None})
                else:
                    code = result[1]
                    if os.WIFEXITED(code):
                        rc = os.WEXITSTATUS(code)
                    elif os.WIFSIGNALED(code):
                        rc = -os.WTERMSIG(code)
                    else:
                        rc = code
                    children.pop(meta["pid"], None)
                    reaped[pid] = rc
                    _send_framed(sock, {"ok": True, "returncode": rc})
                continue
            if op == "wait":
                pid = int(request["pid"])
                if pid in reaped:
                    _send_framed(sock, {"ok": True, "returncode": reaped[pid]})
                    continue
                meta = children.get(pid)
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                timeout = request.get("timeout_seconds")
                deadline = None if timeout is None else time.monotonic() + float(timeout)
                while True:
                    result = os.waitpid(meta["pid"], os.WNOHANG)
                    if result[0] != 0:
                        code = result[1]
                        if os.WIFEXITED(code):
                            rc = os.WEXITSTATUS(code)
                        elif os.WIFSIGNALED(code):
                            rc = -os.WTERMSIG(code)
                        else:
                            rc = code
                        children.pop(meta["pid"], None)
                        reaped[pid] = rc
                        _send_framed(sock, {"ok": True, "returncode": rc})
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        _send_framed(sock, {"ok": False, "error": "timeout"})
                        break
                    time.sleep(0.01)
                continue
            if op == "kill":
                pid = int(request["pid"])
                if pid in reaped:
                    _send_framed(sock, {"ok": True})
                    continue
                meta = children.get(pid)
                if meta is None:
                    _send_framed(sock, {"ok": False, "error": "unknown_pid"})
                    continue
                try:
                    os.kill(meta["pid"], int(request.get("signal", signal.SIGKILL)))
                    _send_framed(sock, {"ok": True})
                except OSError as error:
                    _send_framed(sock, {"ok": False, "error": str(error.errno)})
                continue
            _send_framed(sock, {"ok": False, "error": f"unknown_op:{op}"})
    except BaseException as error:
        try:
            import traceback as _tb

            sock.sendall(
                ("ERR:" + "".join(_tb.format_exception(type(error), error, error.__traceback__))).encode(
                    "utf-8", "replace"
                )[:1500]
            )
        except OSError:
            pass
        os._exit(1)


@dataclass
class SpawnedLauncher:
    """Launcher process started inside the private mount namespace.

    The helper forked this process, so the helper is its parent and this
    controller is its grandparent.  The controller nevertheless *owns* it:
    it holds a pidfd for exit observation, and -- because it made itself a
    child subreaper before the helper was forked -- it inherits the right to
    reap this exact PID the moment the helper dies (M2-B34).
    """

    pid: int
    stdout_fd: int
    stderr_fd: int
    _helper: "PrivateMountHelper"
    _awaiting_release: bool = False
    #: M2-B32.  The *terminal* release outcome.  Set exactly once, never
    #: replaced, never downgraded.
    release_outcome: GateReleaseOutcome | None = None
    _exit_descriptor: int | None = None
    _exit_descriptor_detail: str = ""
    _exit_descriptor_opened: bool = False
    _reap: ReapOutcome | None = None

    # --- M2-B32: terminal, monotonic release truth ---------------------------

    def release(self) -> GateReleaseOutcome:
        """Ask the trusted helper to open the gate and report what is known.

        This never raises on a release failure.  A raised exception cannot say
        which side of the gate write it came from, and the caller needs exactly
        that distinction to decide what it may claim about the command.

        M2-B32.  Once any terminal outcome exists it is returned unchanged.  The
        previous implementation kept only a *released* outcome and rebuilt every
        other answer from ``_awaiting_release``, so a first call reporting
        RELEASE_OUTCOME_UNKNOWN was followed by NOT_RELEASED -- a claim that no
        instruction executed, made by a controller that never knew that.
        """

        if self.release_outcome is not None:
            return self.release_outcome
        if not self._awaiting_release:
            self.release_outcome = GateReleaseOutcome(
                RELEASE_NOT_RELEASED,
                RELEASE_PHASE_NOT_GATED,
                "this launcher was never placed behind a gate",
            )
            return self.release_outcome
        self._awaiting_release = False
        self.release_outcome = monotonic_release_truth(None, self._helper.release(self.pid))
        return self.release_outcome

    def observed_release_outcome(self) -> GateReleaseOutcome:
        """The public release-state accessor.  Never stronger than the truth.

        Before any attempt this reports an interim, explicitly non-terminal
        observation; afterwards it repeats the terminal outcome forever.
        """

        if self.release_outcome is not None:
            return self.release_outcome
        if self._awaiting_release:
            return GateReleaseOutcome(
                RELEASE_NOT_RELEASED,
                RELEASE_PHASE_NOT_REQUESTED,
                "no release request has been sent, so the gate write was never attempted",
            )
        return GateReleaseOutcome(
            RELEASE_NOT_RELEASED,
            RELEASE_PHASE_NOT_GATED,
            "this launcher was never placed behind a gate",
        )

    # --- M2-B34: controller-owned exit observation and reap ------------------

    def exit_descriptor(self) -> int | None:
        """A pidfd for *observing* this launcher's exit; never a right to reap."""

        if not self._exit_descriptor_opened:
            self._exit_descriptor_opened = True
            self._exit_descriptor, self._exit_descriptor_detail = open_process_descriptor(self.pid)
        return self._exit_descriptor

    def close_exit_descriptor(self) -> None:
        if self._exit_descriptor is not None:
            try:
                os.close(self._exit_descriptor)
            except OSError:  # pragma: no cover - already closed
                pass
            self._exit_descriptor = None

    def _signal_owned(self, sig: int) -> dict[str, Any]:
        """Signal this exact launcher without the helper, immune to PID reuse.

        ``pidfd_send_signal`` names the process, not the number, so a launcher
        that already exited and had its PID recycled cannot be confused with an
        unrelated process.  ``os.kill`` is the fallback and is used only while
        this controller has not observed a reap, which is the window in which
        the PID cannot have been reused.
        """

        descriptor = self.exit_descriptor()
        if descriptor is not None and hasattr(signal, "pidfd_send_signal"):
            try:
                signal.pidfd_send_signal(descriptor, int(sig))
                return {"pid": self.pid, "signal": int(sig), "delivered": True, "error": None,
                        "mechanism": "pidfd_send_signal"}
            except ProcessLookupError:
                return {"pid": self.pid, "signal": int(sig), "delivered": False, "error": "ESRCH",
                        "mechanism": "pidfd_send_signal"}
            except OSError as error:
                return {"pid": self.pid, "signal": int(sig), "delivered": False,
                        "error": errno.errorcode.get(error.errno, str(error.errno)),
                        "mechanism": "pidfd_send_signal"}
        if self._reap is not None and self._reap.reaped:
            return {"pid": self.pid, "signal": int(sig), "delivered": False,
                    "error": "ALREADY_REAPED_PID_MAY_BE_REUSED", "mechanism": "refused"}
        evidence = signal_process(self.pid, int(sig))
        evidence["mechanism"] = "kill"
        return evidence

    def terminate_and_reap(
        self,
        *,
        deadline: Deadline | None = None,
        evidence: ProcessOwnershipEvidence | None = None,
    ) -> ProcessOwnershipEvidence:
        """Destroy and reap this launcher within a controller-owned deadline.

        The helper is preferred while it can still answer, because it is the
        launcher's parent and its ``wait`` is the cheapest correct reap.  The
        moment it cannot answer within the controller's deadline it is bypassed
        entirely: the controller signals the launcher through its own pidfd,
        kills and reaps the helper it forked, and then reaps the launcher the
        kernel has reparented to it.  Every step is bounded and every claim is
        recorded separately, so "the domain was killed" is never read as "the
        launcher was reaped".
        """

        whole = deadline or Deadline.after_ms(ABORT_TOTAL_DEADLINE_MS, "terminate_and_reap")
        record = evidence or ProcessOwnershipEvidence()
        record.launcher_pid = self.pid
        record.helper_pid = self._helper.pid
        record.child_subreaper = CHILD_SUBREAPER.state()

        if self._reap is not None and self._reap.reaped:
            # Idempotent: a second cleanup reports the first reap and performs
            # no second one.  Reaping twice is impossible; claiming it is not.
            record.apply_launcher_reap(self._reap)
            record.launcher_exit_observed = True
            record.launcher_reap_code = REAP_ALREADY_REAPED
            record.launcher_reap_detail = f"{self._reap.detail}; this call reaped nothing"
            record.helper_exit_observed = self._helper.exit_observed
            record.helper_reaped = self._helper.reaped
            record.detail = "the launcher was already reaped by an earlier bounded cleanup"
            return record

        # 1. Ask the helper to kill while it can still answer; then signal
        #    directly regardless, because the controller does not depend on it.
        try:
            self._helper.kill(self.pid, signal.SIGKILL, deadline=whole.sub(
                HELPER_CONTROL_RPC_DEADLINE_MS, "helper_kill_rpc"
            ))
        except HelperDeadlineExpired:
            record.record_deadline("helper_kill_rpc")
            record.helper_bypassed = True
        except PrivateWorkspaceError:
            record.helper_bypassed = True
        signalled = self._signal_owned(signal.SIGKILL)
        record.detail = f"controller-owned signal: {signalled}"

        # 2. Observe the exit.  This is a fact about the process, not about who
        #    reaps it, and it is recorded as its own field.
        observed, observation_detail = observe_process_exit(
            self.exit_descriptor(),
            self.pid,
            whole.sub(LAUNCHER_EXIT_OBSERVATION_DEADLINE_MS, "launcher_exit_observation"),
        )
        record.launcher_exit_observed = observed
        record.launcher_exit_detail = observation_detail
        if not observed:
            record.record_deadline("launcher_exit_observation")

        # 3. Reap.  Prefer the helper, which is the launcher's parent.
        if self._helper.protocol_usable:
            try:
                code = self._helper.wait(
                    self.pid,
                    timeout=0.0,
                    deadline=whole.sub(HELPER_CONTROL_RPC_DEADLINE_MS, "helper_wait_rpc"),
                )
                self._reap = ReapOutcome(
                    reaped=True,
                    exit_code=code,
                    reaper_role=REAPER_MOUNT_NAMESPACE_HELPER,
                    reaper_pid=self._helper.pid,
                    detail=f"the trusted mount-namespace helper (pid {self._helper.pid}) reaped {self.pid}",
                )
                record.apply_launcher_reap(self._reap)
                record.launcher_zombie_remains = process_is_zombie(self.pid)
                self.close_exit_descriptor()
                return record
            except HelperDeadlineExpired:
                record.record_deadline("helper_wait_rpc")
                record.helper_bypassed = True
            except (TimeoutError, PrivateWorkspaceError):
                record.helper_bypassed = True

        # 4. The helper cannot answer.  Take ownership: kill and reap it, which
        #    reparents the launcher to this controller, then reap the launcher.
        record.helper_bypassed = True
        helper_state = self._helper.terminate_and_reap(
            deadline=whole.sub(HELPER_REAP_DEADLINE_MS, "helper_reap")
        )
        record.helper_exit_observed = bool(helper_state.get("exit_observed"))
        helper_reap = helper_state.get("reap")
        if isinstance(helper_reap, ReapOutcome):
            record.apply_helper_reap(helper_reap)
        if not record.helper_reaped and not helper_state.get("already_reaped"):
            record.record_deadline("helper_reap")

        outcome = reap_owned_child(
            self.pid,
            whole.sub(LAUNCHER_REAP_DEADLINE_MS, "launcher_reap"),
            role=REAPER_TRUSTED_CONTROLLER,
        )
        if not outcome.reaped and not CHILD_SUBREAPER.active:
            # Without the subreaper the orphaned launcher was reparented to some
            # other ancestor.  That is recorded as an inability to prove a reap,
            # never as a reap performed by an unnamed process.
            outcome = ReapOutcome(
                reaped=False,
                exit_code=None,
                reaper_role=REAPER_NONE,
                reaper_pid=None,
                detail=(
                    f"{outcome.detail}; this controller is not a child subreaper, so an orphaned "
                    "launcher is not reparented here and no reap can be proved"
                ),
                code=REAP_SUBREAPER_UNAVAILABLE,
            )
        self._reap = outcome
        record.apply_launcher_reap(outcome)
        if not outcome.reaped:
            record.record_deadline("launcher_reap")
        record.launcher_zombie_remains = process_is_zombie(self.pid)
        self.close_exit_descriptor()
        return record

    @property
    def reap_outcome(self) -> ReapOutcome | None:
        return self._reap

    def release_owned_subreaper(self, deadline: Deadline | None = None) -> dict[str, Any]:
        """Close out the ownership this effect's helper held (M2-B40).

        The bounded cleanup is not finished while a process-wide flag is still
        held for a helper the cleanup itself destroyed.  Nothing is released
        while the helper is alive: it still owns its acquisition and its own
        shutdown will end it.
        """

        return self._helper.release_subreaper_if_reaped(deadline=deadline)

    # --- helper-mediated operations, each bounded by the controller ----------

    def poll(self) -> int | None:
        try:
            return self._helper.poll(self.pid)
        except HelperDeadlineExpired:
            return self._poll_owned()
        except HelperProtocolBroken:
            return self._poll_owned()

    def _poll_owned(self) -> int | None:
        """Non-blocking controller-owned reap; ``None`` while it is not ours."""

        if self._reap is not None and self._reap.reaped:
            return self._reap.exit_code
        outcome = reap_owned_child(
            self.pid, Deadline.already_expired("owned_poll"), role=REAPER_TRUSTED_CONTROLLER
        )
        if outcome.reaped:
            self._reap = outcome
            return outcome.exit_code
        return None

    def wait(self, timeout: float | None = None) -> int:
        if self._reap is not None and self._reap.reaped:
            return int(self._reap.exit_code if self._reap.exit_code is not None else -9)
        try:
            return self._helper.wait(self.pid, timeout=timeout)
        except (HelperDeadlineExpired, HelperProtocolBroken):
            bound = (
                Deadline.after_ms(LAUNCHER_REAP_DEADLINE_MS, "owned_wait")
                if timeout is None
                else Deadline.after(timeout, "owned_wait")
            )
            outcome = reap_owned_child(self.pid, bound, role=REAPER_TRUSTED_CONTROLLER)
            if not outcome.reaped:
                raise TimeoutError("launcher wait exceeded the controller deadline") from None
            self._reap = outcome
            return int(outcome.exit_code if outcome.exit_code is not None else -9)

    def kill(self, sig: int = signal.SIGKILL) -> None:
        try:
            self._helper.kill(self.pid, sig)
            return
        except (HelperDeadlineExpired, HelperProtocolBroken):
            pass
        delivered = self._signal_owned(sig)
        if not delivered["delivered"] and delivered["error"] not in {"ESRCH", None}:
            raise PrivateWorkspaceError("private_mountns_kill_failed", str(delivered["error"]))

    def send_signal(self, sig: int) -> None:
        self.kill(sig)


# --- M2-B43: protocol closure and lifecycle completion are different states ---
#
# ``close()`` used to answer one question -- "has this been closed?" -- and use
# the answer for two: whether the protocol may still be spoken, and whether
# anything remains to clean up.  A helper that could not be reaped inside the
# deadline therefore had its ownership released anyway and could never be
# retried.  The two questions are now separate, and the second one is answered
# from the facts below rather than from a flag set on entry.

#: The protocol is open; the helper is alive and answering.
HELPER_LIFECYCLE_PROTOCOL_OPEN = "PROTOCOL_OPEN"
#: The protocol is closed and the helper is still a live process.
HELPER_LIFECYCLE_HELPER_ALIVE = "PROTOCOL_CLOSED_HELPER_ALIVE"
#: The helper's exit was observed; nobody has reaped it yet.
HELPER_LIFECYCLE_EXIT_OBSERVED = "PROTOCOL_CLOSED_EXIT_OBSERVED"
#: This controller reaped the helper and still holds its acquisition.
HELPER_LIFECYCLE_REAPED_OWNERSHIP_RETAINED = "REAPED_OWNERSHIP_RETAINED"
#: The helper is reaped, the acquisition is released, and nothing is owed.
HELPER_LIFECYCLE_CLEANUP_COMPLETE = "CLEANUP_COMPLETE"

HELPER_LIFECYCLE_STATES = (
    HELPER_LIFECYCLE_PROTOCOL_OPEN,
    HELPER_LIFECYCLE_HELPER_ALIVE,
    HELPER_LIFECYCLE_EXIT_OBSERVED,
    HELPER_LIFECYCLE_REAPED_OWNERSHIP_RETAINED,
    HELPER_LIFECYCLE_CLEANUP_COMPLETE,
)


class PrivateMountHelper:
    """Long-lived user+mount namespace holding the private tmpfs and spawn service."""

    def __init__(self, pid: int, conn: socket.socket, view_fd: int, staging_path: str) -> None:
        self.pid = pid
        self.conn = conn
        self.view_fd = view_fd
        self.staging_path = staging_path
        # Protocol closure only.  M2-B43: this says the framed protocol may no
        # longer be spoken; it says nothing about whether the helper has been
        # reaped or whether its ownership has ended.
        self._closed = False
        self._graceful = False
        self._cleanup_complete = False
        self._closes = 0
        # M2-B33.  A deadline that expires mid-frame destroys the length-prefixed
        # framing: the controller cannot know how much of a message the helper
        # already sent.  Once that happens the connection is never used again,
        # so a wedged helper costs one deadline in total rather than one per
        # remaining call.
        self._protocol_broken = False
        self._broken_detail = ""
        # M2-B34.  The helper is a direct child of this controller.
        self._reaped = False
        self._reap: ReapOutcome | None = None
        self._exit_observed = False
        self._subreaper_acquired = False
        self._subreaper: SubreaperReference | None = None
        self._subreaper_state: dict[str, Any] = {}
        self._subreaper_released = False
        # M2-B47.  The reference is spent by the release, so the handle that can
        # still make an unsettled restoration terminal is kept separately, and
        # what the single release actually returned is kept immutably beside
        # whatever a later settlement changes.
        self._subreaper_settler: SubreaperReference | None = None
        self._subreaper_release_result: str | None = None
        self._settlements: list[dict[str, Any]] = []
        # M2-B48.  The registry entry that holds this helper's retry handle
        # while its cleanup is incomplete, so the handle outlives every local
        # wrapper that could have dropped it.
        self._registry_id: str | None = None
        self._last_closure: dict[str, Any] = {}
        # M2-B52.  The capacity this helper's cleanup obligation was created
        # under, taken before the fork and converted into exactly one registry
        # entry -- or given back -- when the lifecycle ends.
        self._reservation: Any = None
        self._registration_failure: dict[str, Any] | None = None
        # M2-B53.  A helper handle is reachable from the frame that created it
        # and from the process registry drain at the same time.  One lifecycle
        # transition at a time: the reap, the single release, the settlement and
        # the descriptor closure are performed by exactly one of them.
        self._lifecycle_lock = threading.RLock()

    # --- protocol health ------------------------------------------------------

    @property
    def protocol_usable(self) -> bool:
        return not self._closed and not self._protocol_broken

    @property
    def protocol_broken_detail(self) -> str:
        return self._broken_detail

    @property
    def reaped(self) -> bool:
        return self._reaped

    @property
    def exit_observed(self) -> bool:
        return self._exit_observed

    @property
    def subreaper_state(self) -> dict[str, Any]:
        return dict(self._subreaper_state)

    # --- M2-B43: the lifecycle, as separate facts ------------------------------

    @property
    def protocol_closed(self) -> bool:
        return self._closed

    @property
    def ownership_retained(self) -> bool:
        """Whether this helper still holds the acquisition it was started with."""

        return self._subreaper_acquired

    @property
    def restoration_settled(self) -> bool:
        """Whether the release this helper performed left nothing owed.

        M2-B47.  Two facts, not one: the release result itself, and whether the
        process-wide debt that result latched is still standing.  A settlement
        that read the owed baseline back replaces the first and clears the
        second; nothing else does.
        """

        state = self._subreaper_state
        if state.get("code") in SUBREAPER_UNSETTLED_RESULTS:
            return False
        return not bool(state.get("debt_outstanding"))

    @property
    def settlement_attempts(self) -> int:
        return len(self._settlements)

    @property
    def registry_id(self) -> str | None:
        """The process cleanup-registry entry retaining this helper (M2-B48)."""

        return self._registry_id

    @property
    def cleanup_complete(self) -> bool:
        """Positively reaped, ownership ended, and nothing owed (M2-B43).

        Protocol closure is not this.  A helper whose socket is shut but whose
        process is still an unreaped child of this controller has an incomplete
        cleanup, and saying otherwise is the claim this closes.
        """

        return self._cleanup_complete

    def _recompute_cleanup_locked(self) -> None:
        self._cleanup_complete = bool(
            self._reaped and not self._subreaper_acquired and self.restoration_settled
        )

    def lifecycle(self) -> dict[str, Any]:
        """The eight lifecycle facts, kept apart so none can stand for another."""

        alive = process_present(self.pid) and not self._reaped
        if self._cleanup_complete:
            state = HELPER_LIFECYCLE_CLEANUP_COMPLETE
        elif self._reaped:
            state = HELPER_LIFECYCLE_REAPED_OWNERSHIP_RETAINED
        elif self._exit_observed:
            state = HELPER_LIFECYCLE_EXIT_OBSERVED
        elif self._closed:
            state = HELPER_LIFECYCLE_HELPER_ALIVE
        else:
            state = HELPER_LIFECYCLE_PROTOCOL_OPEN
        return {
            "state": state,
            "helper_pid": self.pid,
            "protocol_open": not self._closed,
            "protocol_closed": self._closed,
            "helper_alive": alive,
            "helper_zombie": process_is_zombie(self.pid),
            "helper_exit_observed": self._exit_observed,
            "helper_reaped": self._reaped,
            "ownership_retained": self._subreaper_acquired,
            "ownership_released": self._subreaper_released,
            "restoration_settled": self.restoration_settled,
            "restoration_settlement_attempts": len(self._settlements),
            "cleanup_complete": self._cleanup_complete,
            "cleanup_registry_id": self._registry_id,
            "close_calls": self._closes,
        }

    def _break_protocol(self, detail: str) -> None:
        self._protocol_broken = True
        if not self._broken_detail:
            self._broken_detail = detail

    def _rpc(
        self,
        payload: dict[str, Any],
        deadline: Deadline,
        operation: str,
        *,
        fds: tuple[int, ...] = (),
    ) -> tuple[dict[str, Any], list[int]]:
        """One bounded request/response round trip with the trusted helper."""

        if self._closed:
            raise PrivateWorkspaceError("private_mountns_helper_closed", operation)
        if self._protocol_broken:
            raise HelperProtocolBroken(f"{operation}: {self._broken_detail}")
        try:
            _send_framed_within(self.conn, payload, fds, deadline, operation)
            return _recv_framed_within(self.conn, deadline, operation)
        except HelperDeadlineExpired as error:
            self._break_protocol(str(error))
            raise
        except PrivateWorkspaceError as error:
            self._break_protocol(f"{operation}: {error}")
            raise
        except (OSError, ValueError) as error:
            # A reset, a closed peer, or an unparseable frame all mean the same
            # thing to the caller: this helper can no longer answer.  They are
            # classified rather than allowed to escape as a raw transport error,
            # so every caller has one refusal type to handle.
            self._break_protocol(f"{operation}: {error}")
            raise PrivateWorkspaceError(
                "private_mountns_helper_closed", f"{operation}: {error}"
            ) from error

    @classmethod
    def start(cls, *, size: str = DEFAULT_PRIVATE_TMPFS_SIZE) -> "PrivateMountHelper":
        """Fork the trusted helper, or create nothing at all.

        M2-B37.  The subreaper acquisition is the first thing this method does
        and the launch cannot proceed without it.  The flag must be held
        *before* the fork so that a helper which dies at any point afterwards --
        including before it ever creates the launcher -- leaves its orphans
        reparented to this controller rather than to an unrelated init.  A
        controller that could not establish it would be forking a helper whose
        orphans it has no right to reap, so it does not fork at all: no socket
        pair, no child, no pidfd, and no helper object exist on that path.

        M2-B38.  Between the acquisition and the successful ownership transfer
        at the end, every exit path destroys and reaps the partially created
        child, closes every descriptor this method opened, and releases the
        acquisition exactly once.
        """

        if not hasattr(os, "unshare"):
            raise PrivateWorkspaceError("private_mountns_unavailable", "os.unshare is absent")
        # M2-B48/M2-B52.  A process already holding its capacity of unresolved
        # cleanups forks nothing further.  The capacity is *reserved* rather than
        # merely checked, so the fork below cannot happen against a capacity
        # another thread took in between, and the reservation is what the
        # obligation this helper may become is later registered under.  Refusing
        # here is fail-closed and pre-effect: no acquisition, no socket pair, no
        # child, and no descriptor exists on this path, exactly as an unavailable
        # acquisition leaves none.
        reservation = _CLEANUP_REGISTRY.reserve("private-mount-helper")
        try:
            subreaper = CHILD_SUBREAPER.acquire_reference()
        except ChildSubreaperUnavailable as error:
            # Nothing was created, so there is nothing to clean up, and the
            # process-wide flag is exactly as this call found it.
            reservation.release()
            raise PrivateWorkspaceError(
                "private_mountns_subreaper_unavailable",
                f"{error.code}: {error.detail}; no helper was forked and no launcher exists",
            ) from error
        parent: socket.socket | None = None
        child: socket.socket | None = None
        pid: int | None = None
        received_fds: list[int] = []
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            deadline = Deadline.after_ms(HELPER_STARTUP_DEADLINE_MS, "helper_startup")
            pid = _fork()
            if pid == 0:  # pragma: no cover - child process
                # The child never runs the parent's rollback: the flag is not
                # inherited, pid 0 is not an addressable process, and an
                # exception here must not let helper code escape into the
                # controller's own failure path.
                try:
                    parent.close()
                    _helper_main(child, size=size)
                finally:
                    os._exit(0)
            child.close()
            child = None
            parent.settimeout(max(deadline.remaining_seconds, 0.001))
            ready = parent.recv(5)
            if ready != b"READY":
                raise PrivateWorkspaceError(
                    "private_mountns_tmpfs_failed",
                    ready.decode("utf-8", "replace"),
                )
            uid = os.getuid()
            gid = os.getgid()
            Path(f"/proc/{pid}/setgroups").write_text("deny\n", encoding="ascii")
            Path(f"/proc/{pid}/uid_map").write_text(f"{uid} {uid} 1\n", encoding="ascii")
            Path(f"/proc/{pid}/gid_map").write_text(f"{gid} {gid} 1\n", encoding="ascii")
            parent.settimeout(max(deadline.remaining_seconds, 0.001))
            parent.sendall(b"MAPS")
            parent.settimeout(max(deadline.remaining_seconds, 0.001))
            msg, anc, _flags, _addr = parent.recvmsg(4096, socket.CMSG_SPACE(4))
            if not msg.startswith(b"OKFD"):
                detail = msg.decode("utf-8", "replace")
                raise PrivateWorkspaceError("private_mountns_tmpfs_failed", detail)
            staging = msg[4:].decode("utf-8")
            for level, typ, data in anc:
                if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                    received_fds.extend(array.array("i", data).tolist())
            if not received_fds:
                raise PrivateWorkspaceError("private_mountns_tmpfs_failed", "missing-fd")
            parent.settimeout(None)
            helper = cls(pid, parent, received_fds[0], staging)
            # Ownership of the acquisition, the socket, and the view descriptor
            # transfers to the helper object here.  Past this line the rollback
            # below is not reachable, and helper.close() owns the release.
            helper._subreaper = subreaper
            helper._subreaper_acquired = True
            helper._subreaper_state = subreaper.state
            helper._reservation = reservation
            return helper
        except BaseException as error:
            rollback = _roll_back_failed_start(
                pid=pid, sockets=(parent, child), descriptors=tuple(received_fds), subreaper=subreaper
            )
            # The helper object was never handed the reservation, so the capacity
            # this start took is given straight back.  A failed start that could
            # not be reaped is retained by ``_UNSETTLED_FAILED_STARTS`` and is
            # accounted there, not here.
            reservation.release()
            if isinstance(error, TimeoutError):
                raise HelperDeadlineExpired(
                    "helper_startup",
                    f"the trusted helper did not become ready: {error}; rollback={rollback}",
                ) from error
            if isinstance(error, OSError) and not isinstance(error, PrivateWorkspaceError):
                # fork(), socketpair() and the /proc map writes all fail as
                # OSError.  They are classified rather than allowed to escape
                # raw, so every caller has one refusal type for "the helper was
                # never created".
                raise PrivateWorkspaceError(
                    "private_mountns_helper_start_failed",
                    f"{errno.errorcode.get(error.errno, error.errno)}: {error}; rollback={rollback}",
                ) from error
            raise

    def spawn(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        pass_fds: tuple[int, ...] = (),
        await_release: bool = False,
    ) -> SpawnedLauncher:
        if self._closed:
            raise PrivateWorkspaceError("private_mountns_helper_closed", "spawn")
        reply, fds = self._rpc(
            {
                "op": "spawn",
                "argv": list(argv),
                "parent_fds": list(pass_fds),
                "await_release": bool(await_release),
            },
            Deadline.after_ms(HELPER_CONTROL_RPC_DEADLINE_MS, "helper_spawn_rpc"),
            "spawn",
            fds=pass_fds,
        )
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_spawn_failed", str(reply.get("error")))
        if len(fds) < 2:
            raise PrivateWorkspaceError("private_mountns_spawn_failed", "missing_stdio_fds")
        return SpawnedLauncher(
            pid=int(reply["pid"]),
            stdout_fd=fds[0],
            stderr_fd=fds[1],
            _helper=self,
            _awaiting_release=bool(reply.get("await_release")),
        )

    #: Trusted fault seam for the M2-B30/M2-B33 protocol tests.  It is set only
    #: by test code on the controller side; the untrusted command never speaks
    #: this protocol and cannot reach it.
    release_fault: str | None = None

    def release(self, pid: int) -> GateReleaseOutcome:
        """Two-phase gate release, bounded by the controller.  Never raises.

        Each acknowledgement has its own controller-owned deadline.  Expiry
        before the accept frame and expiry after it are different phases, but
        both are RELEASE_OUTCOME_UNKNOWN: in either case the helper may already
        have written the gate, and this controller did not see it happen.  The
        only outcomes that positively prove non-release are a terminal first
        frame and a reported write failure -- statements the helper made about
        a write it did not perform.
        """

        if self._closed or self._protocol_broken:
            # No release request was ever put on the wire, so the helper cannot
            # have written the gate.  That is a proof of non-release, not an
            # inference from a failure.
            return GateReleaseOutcome(
                RELEASE_NOT_RELEASED,
                RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
                f"no release request was sent: {self._broken_detail or 'the helper is closed'}",
            )
        request: dict[str, Any] = {"op": "release", "pid": pid}
        if self.release_fault:
            request["fault"] = self.release_fault
        accept_deadline = Deadline.after_ms(HELPER_RELEASE_ACCEPT_DEADLINE_MS, "release_accept")
        try:
            _send_framed_within(self.conn, request, (), accept_deadline, "release_request")
        except HelperDeadlineExpired as error:
            self._break_protocol(str(error))
            return GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN,
                RELEASE_PHASE_REQUEST_NOT_SENT,
                f"the release request could not be delivered within the controller deadline: {error}",
            )
        except OSError as error:
            # A partially delivered frame leaves the helper blocked rather than
            # releasing, but this controller cannot see which happened.
            self._break_protocol(f"release_request: {error}")
            return GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN,
                RELEASE_PHASE_REQUEST_NOT_SENT,
                f"the release request could not be delivered: {error}",
            )
        accept: dict[str, Any] | None = None
        completion: dict[str, Any] | None = None
        transport = ""
        try:
            accept, _fds = _recv_framed_within(self.conn, accept_deadline, "release_accept")
        except HelperDeadlineExpired as error:
            self._break_protocol(str(error))
            return GateReleaseOutcome(
                RELEASE_OUTCOME_UNKNOWN,
                RELEASE_PHASE_ACCEPT_DEADLINE_EXPIRED,
                (
                    "the helper did not acknowledge acceptance within the controller deadline; it "
                    f"may have written the gate without this controller seeing it: {error}"
                ),
            )
        except (OSError, ValueError, PrivateWorkspaceError) as error:
            self._break_protocol(f"release_accept: {error}")
            transport = f"the accept frame was not received: {error}"
        if accept is not None and str(accept.get("phase") or "") == RELEASE_PHASE_ACCEPTED:
            completion_deadline = Deadline.after_ms(
                HELPER_RELEASE_COMPLETION_DEADLINE_MS, "release_completion"
            )
            try:
                completion, _fds = _recv_framed_within(
                    self.conn, completion_deadline, "release_completion"
                )
            except HelperDeadlineExpired as error:
                self._break_protocol(str(error))
                return GateReleaseOutcome(
                    RELEASE_OUTCOME_UNKNOWN,
                    RELEASE_PHASE_COMPLETION_DEADLINE_EXPIRED,
                    (
                        "the helper accepted the request and then reported nothing within the "
                        f"controller deadline; the gate write may have completed: {error}"
                    ),
                )
            except (OSError, ValueError, PrivateWorkspaceError) as error:
                self._break_protocol(f"release_completion: {error}")
                transport = f"the completion frame was not received: {error}"
        return classify_release_frames(accept, completion, transport_detail=transport)

    def poll(self, pid: int, *, deadline: Deadline | None = None) -> int | None:
        reply, _fds = self._rpc(
            {"op": "poll", "pid": pid},
            deadline or Deadline.after_ms(HELPER_CONTROL_RPC_DEADLINE_MS, "helper_poll_rpc"),
            "poll",
        )
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_poll_failed", str(reply.get("error")))
        return reply.get("returncode")

    def wait(self, pid: int, timeout: float | None = None, *, deadline: Deadline | None = None) -> int:
        payload: dict[str, Any] = {"op": "wait", "pid": pid}
        if timeout is not None:
            payload["timeout_seconds"] = float(timeout)
        # The helper may honour ``timeout`` itself.  The controller does not rely
        # on that: its own bound is the caller's timeout plus a fixed margin, or
        # the flat control-RPC deadline when the caller asked to wait forever.
        if deadline is None:
            milliseconds = (
                HELPER_CONTROL_RPC_DEADLINE_MS
                if timeout is None
                else int(timeout * 1000) + HELPER_WAIT_RPC_MARGIN_MS
            )
            deadline = Deadline.after_ms(milliseconds, "helper_wait_rpc")
        reply, _fds = self._rpc(payload, deadline, "wait")
        if not reply.get("ok"):
            if reply.get("error") == "timeout":
                raise TimeoutError("launcher wait timed out")
            raise PrivateWorkspaceError("private_mountns_wait_failed", str(reply.get("error")))
        return int(reply["returncode"])

    def kill(self, pid: int, sig: int = signal.SIGKILL, *, deadline: Deadline | None = None) -> None:
        reply, _fds = self._rpc(
            {"op": "kill", "pid": pid, "signal": int(sig)},
            deadline or Deadline.after_ms(HELPER_CONTROL_RPC_DEADLINE_MS, "helper_kill_rpc"),
            "kill",
        )
        if not reply.get("ok"):
            raise PrivateWorkspaceError("private_mountns_kill_failed", str(reply.get("error")))

    def _release_subreaper(self) -> dict[str, Any]:
        """Release this helper's acquisition once, whoever asks first.

        ``close`` and the bounded abort path both reach this; the first one
        releases and every later one reports that release rather than
        performing a second (M2-B38, M2-B39).

        M2-B43.  Every caller must already have proved the helper is reaped.
        This method does not re-derive that: it is the single release site, and
        the ordering is enforced at each of the three call sites that can reach
        it, each of which refuses to call it over a live or unreaped helper.

        M2-B53.  Serialised: a local close and a registry drain reaching this
        helper concurrently release its acquisition exactly once between them.
        """

        with self._lifecycle_lock:
            return self._release_subreaper_locked()

    def _release_subreaper_locked(self) -> dict[str, Any]:
        if not self._subreaper_acquired:
            return dict(self._subreaper_state)
        self._subreaper_acquired = False
        reference = self._subreaper
        self._subreaper = None
        # M2-B47.  The reference may be released exactly once, and is; the
        # handle is retained separately because settling what that release could
        # not observe is a different operation on the same process-wide domain,
        # and a cleanup advertised as retryable must be able to reach it.
        self._subreaper_settler = reference
        self._subreaper_state = reference.release() if reference is not None else CHILD_SUBREAPER.release()
        self._subreaper_release_result = self._subreaper_state.get("code")
        self._subreaper_released = True
        self._recompute_cleanup_locked()
        return dict(self._subreaper_state)

    def _settle_restoration_debt(self) -> dict[str, Any]:
        """Make an unsettled restoration terminal, or leave it standing (M2-B47).

        ``prctl`` does not block, so this costs a bounded cleanup nothing and is
        attempted on the call that discovers the debt as well as on every later
        one.  It claims nothing it did not read back: the ownership document it
        records is the one the settlement returned.

        M2-B53.  Serialised with the release it follows and the reap before it.
        """

        with self._lifecycle_lock:
            return self._settle_restoration_debt_locked()

    def _settle_restoration_debt_locked(self) -> dict[str, Any]:
        if not self._subreaper_released or self.restoration_settled:
            return {}
        settler = self._subreaper_settler
        settlement = (
            settler.settle_restoration_debt()
            if settler is not None
            else CHILD_SUBREAPER.settle_restoration_debt()
        )
        self._settlements.append(settlement)
        if settlement.get("settled"):
            self._subreaper_state = dict(settlement["state"])
        self._recompute_cleanup_locked()
        return settlement

    def release_subreaper_if_reaped(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """Release ownership for a helper this controller has already reaped.

        M2-B40.  When the bounded abort path takes the helper over -- kills it
        and reaps it -- that helper will never run its own shutdown, so the
        process-wide acquisition justified by its lifetime would outlive every
        process that justified it.  Releasing it belongs to the same bounded
        cleanup.

        ``prctl`` does not block, so the deadline bounds the *ledger entry* for
        this stage rather than a wait: an exhausted budget still performs the
        restoration, because refusing to restore a process-wide flag would leave
        a worse residual than performing one non-blocking pair of syscalls.  The
        restoration is still only *claimed* from its readback.
        """

        with self._lifecycle_lock:
            return self._release_subreaper_if_reaped_locked(deadline=deadline)

    def _release_subreaper_if_reaped_locked(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        bound = deadline or Deadline.after_ms(SUBREAPER_RESTORE_DEADLINE_MS, "subreaper_release")
        if not self._subreaper_acquired:
            return {
                "performed": False,
                "reason": "this helper holds no acquisition to release",
                "result": dict(self._subreaper_state),
                "helper_reaped": self._reaped,
                "ownership_retained": False,
                "deadline": bound.to_dict(),
            }
        if not self._reaped:
            # M2-B43.  The ordering is the invariant: ownership outlives an
            # unreaped helper, never the other way round.
            return {
                "performed": False,
                "reason": "the helper is alive and still owns its acquisition",
                "result": dict(self._subreaper_state),
                "helper_reaped": False,
                "ownership_retained": True,
                "deadline": bound.to_dict(),
            }
        return {
            "performed": True,
            "reason": "the trusted controller reaped this helper, so its acquisition ends here",
            "result": self._release_subreaper(),
            "helper_reaped": True,
            "ownership_retained": self._subreaper_acquired,
            "deadline": bound.to_dict(),
        }

    def terminate_and_reap(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """Kill and reap the helper this controller forked, boundedly.

        This is the controller-owned escape from a helper that is alive but
        cannot answer.  Reaping the helper is also what hands the launcher to
        this controller: the kernel reparents the orphan to the nearest
        subreaper ancestor, which is this process.

        M2-B53.  Serialised: a concurrent close and abort kill and reap this
        helper exactly once between them.
        """

        with self._lifecycle_lock:
            return self._terminate_and_reap_locked(deadline=deadline)

    def _terminate_and_reap_locked(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        bound = deadline or Deadline.after_ms(HELPER_REAP_DEADLINE_MS, "helper_reap")
        state: dict[str, Any] = {
            "helper_pid": self.pid,
            "already_reaped": self._reaped,
            "exit_observed": self._exit_observed,
            "signal": None,
            "reap": self._reap,
        }
        if self._reaped:
            return state
        state["signal"] = signal_process(self.pid, signal.SIGKILL)
        descriptor, _detail = open_process_descriptor(self.pid)
        try:
            observed, _observation = observe_process_exit(descriptor, self.pid, bound)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:  # pragma: no cover - already closed
                    pass
        self._exit_observed = observed or self._exit_observed
        outcome = reap_owned_child(self.pid, bound, role=REAPER_TRUSTED_CONTROLLER)
        self._reap = outcome
        self._reaped = outcome.reaped
        if outcome.reaped:
            self._exit_observed = True
        self._break_protocol("the helper was killed and reaped by the trusted controller")
        self._recompute_cleanup_locked()
        state["exit_observed"] = self._exit_observed
        state["reap"] = outcome
        state["lifecycle"] = self.lifecycle()
        return state

    def close(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """Shut the helper down within one controller-owned deadline.

        M2-B40.  Every step spends the *same* instant.  The cooperative steps --
        the shutdown exchange and the wait for a voluntary exit -- share a
        bounded *prefix* of it, and the forced kill-and-reap takes what is left,
        so the shutdown cannot cost a cooperative deadline plus a fresh reap
        deadline after it and the cooperative steps cannot spend the guarantee.
        A caller inside a larger bounded cleanup passes its own remaining time,
        and this shutdown cannot outlive it.

        M2-B53.  The whole shutdown is one serialised lifecycle transition: a
        local close and a registry drain arriving together perform one reap, one
        release and one settlement between them, and both receive the same
        coherent closure document.
        """

        with self._lifecycle_lock:
            return self._close_locked(deadline=deadline)

    def _close_locked(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        whole = deadline or Deadline.after_ms(HELPER_SHUTDOWN_DEADLINE_MS, "helper_shutdown")
        if self._closed and self._cleanup_complete:
            # Terminal.  The protocol is closed, the helper is reaped, its
            # ownership is released, and nothing is owed, so there is nothing
            # left for a repeat to do.  Both conditions are required: the
            # bounded abort path can reap the helper and end its ownership
            # before any shutdown runs, and the socket and view descriptor this
            # object still owns are closed exactly once, below.
            return self._closure_evidence(whole, already_closed=True, released_here=False)
        self._closes += 1
        first = not self._closed
        self._closed = True
        # The cooperative prefix.  A helper that will not answer, or will not
        # exit, spends only this much of the whole; the rest belongs to the
        # kill-and-reap that does not depend on it.
        cooperative = whole.sub(HELPER_COOPERATIVE_EXIT_DEADLINE_MS, "helper_cooperative_exit")
        if first:
            if not self._protocol_broken:
                try:
                    _send_framed_within(self.conn, {"op": "exit"}, (), cooperative, "shutdown")
                    _recv_framed_within(self.conn, cooperative, "shutdown")
                    self._graceful = True
                except Exception:
                    self._graceful = False
            try:
                self.conn.close()
            except OSError:  # pragma: no cover - already closed
                pass
            try:
                os.close(self.view_fd)
            except OSError:  # pragma: no cover - already closed
                pass
        if not self._reaped:
            # Still the cooperative prefix on the first close, so the forced
            # path below always has what is left of the same bound.  A retry has
            # already asked this helper to exit and has already closed the
            # socket it would have answered on, so it spends nothing waiting for
            # a request it cannot repeat: one non-blocking observation, then the
            # forced path within the budget this call was given.
            patient = cooperative if first else Deadline.already_expired("helper_retry_probe")
            outcome = reap_owned_child(self.pid, patient, role=REAPER_TRUSTED_CONTROLLER)
            if not outcome.reaped:
                # It did not exit on request within its share of the deadline.
                # It is this controller's child, so it is killed and reaped
                # here, within what remains of the same instant.
                signal_process(self.pid, signal.SIGKILL)
                outcome = reap_owned_child(
                    self.pid,
                    whole.sub(HELPER_REAP_DEADLINE_MS, "helper_forced_reap"),
                    role=REAPER_TRUSTED_CONTROLLER,
                )
            self._reap = outcome
            self._reaped = outcome.reaped
            self._exit_observed = self._exit_observed or outcome.reaped
        # M2-B43.  The release is conditional on the reap, and on nothing else.
        # An unreaped helper keeps its ownership: releasing here would hand back
        # the process-wide flag that gives this controller the right to reap the
        # very process it just failed to reap, and would leave a zombie whose
        # reaper nobody can name.
        released_here = False
        if self._reaped:
            released_here = self._subreaper_acquired
            # The public, serialising entry point: the lifecycle lock is
            # re-entrant, so this is the same single release site every other
            # caller reaches rather than a second, private one.
            self._release_subreaper()
        # M2-B47.  The release is spent; what it could not observe is settled
        # here.  This is what makes the advertised retry a retry: without it a
        # repeated close reaped nothing, released nothing, and returned
        # cleanup_retryable=true for ever.
        settlement = self._settle_restoration_debt()
        self._recompute_cleanup_locked()
        return self._closure_evidence(
            whole, already_closed=False, released_here=released_here, settlement=settlement
        )

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """The one retry protocol every retained cleanup handle answers (M2-B48)."""

        return self.close(deadline=deadline)

    def cleanup_evidence(self) -> dict[str, Any]:
        """The last closure document, without performing another closure."""

        return dict(self._last_closure)

    def _closure_evidence(
        self,
        whole: Deadline,
        *,
        already_closed: bool,
        released_here: bool,
        settlement: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """What this shutdown did, and what it left undone (M2-B43, M2-B47)."""

        evidence = {
            "helper_pid": self.pid,
            "already_closed": already_closed,
            "graceful_shutdown": self._graceful,
            "reaped": self._reaped,
            "exit_code": None if self._reap is None else self._reap.exit_code,
            "reaper_role": REAPER_NONE if self._reap is None else self._reap.reaper_role,
            "reaper_pid": None if self._reap is None else self._reap.reaper_pid,
            "reap_code": None if self._reap is None else self._reap.code,
            "reap_detail": "" if self._reap is None else self._reap.detail,
            "subreaper": dict(self._subreaper_state),
            "subreaper_released_by_this_call": released_here,
            "subreaper_release_result": self._subreaper_release_result,
            "restoration_settlement": dict(settlement or {}),
            "settlement_attempts": len(self._settlements),
            "debt_outstanding": process_restoration_debt() is not None,
            "ownership_generation": ownership_generation(),
            "ownership_retained": self._subreaper_acquired,
            "restoration_settled": self.restoration_settled,
            "cleanup_complete": self._cleanup_complete,
            "cleanup_retryable": not self._cleanup_complete,
            "helper_present": process_present(self.pid),
            "helper_zombie": process_is_zombie(self.pid),
            "lifecycle": self.lifecycle(),
            "deadline": whole.to_dict(),
        }
        # M2-B47.  A retryable cleanup names the operation that can make it
        # terminal, so "retryable" is a reachable statement rather than a hope.
        evidence["cleanup_retry_operation"] = _cleanup_retry_operation(evidence)
        # M2-B48.  Registration is the last step, so the entry it creates
        # carries the evidence this call produced.
        #
        # M2-B52.  It is also a step that can fail, and a failure here used to be
        # swallowed: the closure returned an ordinary document advertising a
        # retry, with no registry id and no surviving process-level handle, so
        # the obligation existed and nothing could reach it.  The failure is now
        # typed, the cleanup is not called complete over it, and the handle is
        # retained at process level until a later drain registers or settles it.
        self._last_closure = evidence
        try:
            evidence["cleanup_registry_id"] = _CLEANUP_REGISTRY.record(
                self, evidence, reservation=self._reservation
            )
        except Exception as error:
            self._registration_failure = {
                "code": "CLEANUP_REGISTRATION_FAILED",
                "error": type(error).__name__,
                "detail": str(error),
                "helper_pid": self.pid,
            }
            evidence["cleanup_registry_id"] = None
            evidence["cleanup_registration_failure"] = dict(self._registration_failure)
            evidence["cleanup_complete"] = False
            evidence["cleanup_retryable"] = True
            evidence["cleanup_retry_operation"] = CLEANUP_RETRY_REGISTER
            _retain_unregistered_cleanup(self)
            self._last_closure = evidence
            return evidence
        self._registration_failure = None
        evidence["cleanup_registration_failure"] = None
        _release_unregistered_cleanup(self)
        if self._reservation is not None and not getattr(self._reservation, "active", False):
            # The reservation was either converted into the entry above or given
            # back with the completion; either way this helper no longer holds
            # capacity it is not using.
            self._reservation = None
        self._last_closure = evidence
        return evidence


def _kill_and_reap_owned(pid: int, deadline: Deadline) -> ReapOutcome:
    """Destroy and reap one PID this controller forked, within a deadline."""

    signal_process(pid, signal.SIGKILL)
    return reap_owned_child(pid, deadline, role=REAPER_TRUSTED_CONTROLLER)


def host_can_pathname_reach(view_fd: int) -> bool:
    """Return True if a same-UID host pathname opens the same inode as view_fd."""

    try:
        info = os.fstat(view_fd)
    except OSError:
        return False
    try:
        path = os.readlink(f"/proc/self/fd/{view_fd}")
    except OSError:
        return False
    if not path or path.startswith("anon_inode:"):
        return False
    try:
        candidate = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        other = os.fstat(candidate)
        # Same path string can name an empty host directory while view_fd names
        # the private tmpfs.  Compare device/inode.
        return other.st_dev == info.st_dev and other.st_ino == info.st_ino
    finally:
        os.close(candidate)


def _entry_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular_file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "other"


def _is_ipc_or_special(kind: str) -> bool:
    return kind in {"socket", "fifo", "block_device", "character_device", "other"}


def _symlink_is_exportable(target: str) -> bool:
    if not target or "\x00" in target:
        return False
    if target.startswith("/") or target.startswith("\\"):
        return False
    parts = Path(target).parts
    return ".." not in parts


def _walk_tree(root_fd: int) -> Iterator[tuple[str, os.stat_result]]:
    stack: list[tuple[int, str]] = [(root_fd, ".")]
    owned: list[int] = []
    try:
        while stack:
            dir_fd, prefix = stack.pop()
            with os.scandir(dir_fd) as entries:
                for entry in entries:
                    relative = entry.name if prefix == "." else f"{prefix}/{entry.name}"
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise PrivateWorkspaceError("tree_walk_failed", f"{relative}:{error.errno}") from error
                    yield relative, info
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
                        owned.append(child)
                        stack.append((child, relative))
    finally:
        for handle in owned:
            try:
                os.close(handle)
            except OSError:
                pass


def _hash_regular_at(dir_fd: int, name: str) -> tuple[str, int]:
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(handle, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MATERIALIZE_BYTES:
                raise PrivateWorkspaceError("materialize_byte_limit", name)
            digest.update(chunk)
        return digest.hexdigest(), total
    finally:
        os.close(handle)


def _open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    if relative in {"", "."}:
        return os.dup(root_fd), "."
    parts = relative.split("/")
    leaf = parts[-1]
    dir_fd = root_fd
    owned: list[int] = []
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            owned.append(nxt)
            dir_fd = nxt
        result = os.dup(dir_fd)
        return result, leaf
    finally:
        for handle in owned:
            try:
                os.close(handle)
            except OSError:
                pass


def snapshot_tree_identity(root_fd: int) -> tuple[str, int, int, tuple[str, ...]]:
    digest = hashlib.sha256()
    entries = 0
    total_bytes = 0
    specials: list[str] = []
    for relative, info in sorted(_walk_tree(root_fd), key=lambda item: item[0]):
        entries += 1
        if entries > MAX_EXPORT_ENTRIES:
            raise PrivateWorkspaceError("tree_entry_limit", str(entries))
        kind = _entry_kind(info.st_mode)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(kind.encode("utf-8"))
        digest.update(b"\x00")
        if kind == "regular_file":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                sha, size = _hash_regular_at(parent_fd, leaf)
            finally:
                os.close(parent_fd)
            total_bytes += size
            digest.update(sha.encode("ascii"))
            digest.update(b"\x00")
            digest.update(str(size).encode("ascii"))
        elif kind == "symlink":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                target = os.readlink(leaf, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            digest.update(target.encode("utf-8", "surrogateescape"))
        elif kind == "directory":
            digest.update(b"dir")
        else:
            specials.append(f"{kind}:{relative}")
            digest.update(b"special")
        digest.update(b"\n")
    return digest.hexdigest(), entries, total_bytes, tuple(specials)


@dataclass(frozen=True)
class SourceSnapshotIdentity(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_SOURCE_SNAPSHOT_IDENTITY
    LABEL: ClassVar[str] = "source snapshot identity"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "source_root",
        "device",
        "inode",
        "tree_sha256",
        "entry_count",
        "total_regular_file_bytes",
        "special_inode_count",
    )

    source_root: str
    device: int
    inode: int
    tree_sha256: str
    entry_count: int
    total_regular_file_bytes: int
    special_inode_count: int
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "SourceSnapshotIdentity":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.source_root, "source_root", max_bytes=4096)
        _require_text(self.tree_sha256, "tree_sha256", max_bytes=64)
        if len(self.tree_sha256) != 64:
            raise ObservationError("tree_sha256 must be a sha256 hex digest")
        for name in ("device", "inode", "entry_count", "total_regular_file_bytes", "special_inode_count"):
            _require_int(getattr(self, name), name)


@dataclass(frozen=True)
class PrivateExecutionViewIdentity(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY
    LABEL: ClassVar[str] = "private execution view identity"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "view_root",
        "device",
        "inode",
        "source_snapshot_fingerprint",
        "tree_sha256",
        "entry_count",
        "materialization_kind",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _decode_fp,
    }

    view_root: str
    device: int
    inode: int
    source_snapshot_fingerprint: Fingerprint
    tree_sha256: str
    entry_count: int
    materialization_kind: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "PrivateExecutionViewIdentity":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.view_root, "view_root", max_bytes=4096)
        _require_text(self.tree_sha256, "tree_sha256", max_bytes=64)
        _require_text(self.materialization_kind, "materialization_kind", max_bytes=64)
        self.source_snapshot_fingerprint.validated()
        for name in ("device", "inode", "entry_count"):
            _require_int(getattr(self, name), name)


@dataclass(frozen=True)
class ProposedExportChangeSet(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_PROPOSED_EXPORT_CHANGE_SET
    LABEL: ClassVar[str] = "proposed export change set"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "change_count",
        "operations",
        "paths",
        "change_set_sha256",
        "unsupported_inode_count",
        "unsupported_inodes",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "operations": _encode_strings,
        "paths": _encode_strings,
        "unsupported_inodes": _encode_strings,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "operations": _decode_strings,
        "paths": _decode_strings,
        "unsupported_inodes": _decode_strings,
    }

    change_count: int
    operations: tuple[str, ...]
    paths: tuple[str, ...]
    change_set_sha256: str
    unsupported_inode_count: int
    unsupported_inodes: tuple[str, ...]
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ProposedExportChangeSet":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_int(self.change_count, "change_count")
        _require_int(self.unsupported_inode_count, "unsupported_inode_count")
        _require_text(self.change_set_sha256, "change_set_sha256", max_bytes=64)
        _encode_strings(self.operations)
        _encode_strings(self.paths)
        _encode_strings(self.unsupported_inodes)
        if self.change_count != len(self.operations) or self.change_count != len(self.paths):
            raise ObservationError("change set counts do not agree")
        if self.unsupported_inode_count != len(self.unsupported_inodes):
            raise ObservationError("unsupported inode counts do not agree")
        for operation in self.operations:
            if operation not in EXPORT_OPERATIONS:
                raise ObservationError(f"unsupported export operation {operation}")


@dataclass(frozen=True)
class ExportReservation(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RESERVATION
    LABEL: ClassVar[str] = "export reservation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "source_snapshot_fingerprint",
        "private_view_fingerprint",
        "change_set_fingerprint",
        "state",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _encode_fp,
        "private_view_fingerprint": _encode_fp,
        "change_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "source_snapshot_fingerprint": _decode_fp,
        "private_view_fingerprint": _decode_fp,
        "change_set_fingerprint": _decode_fp,
    }

    reservation_id: str
    source_snapshot_fingerprint: Fingerprint
    private_view_fingerprint: Fingerprint
    change_set_fingerprint: Fingerprint
    state: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReservation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        self.source_snapshot_fingerprint.validated()
        self.private_view_fingerprint.validated()
        self.change_set_fingerprint.validated()


@dataclass(frozen=True)
class ExportReceipt(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RECEIPT
    LABEL: ClassVar[str] = "export receipt"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "applied_count",
        "state",
        "refusal_code",
        "change_set_fingerprint",
    )
    ENCODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "change_set_fingerprint": _encode_fp,
    }
    DECODERS: ClassVar[dict[str, Callable[[Any], Any]]] = {
        "change_set_fingerprint": _decode_fp,
    }

    reservation_id: str
    applied_count: int
    state: str
    refusal_code: str
    change_set_fingerprint: Fingerprint
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReceipt":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        _require_text(self.refusal_code, "refusal_code", max_bytes=256)
        _require_int(self.applied_count, "applied_count")
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        self.change_set_fingerprint.validated()


@dataclass(frozen=True)
class ExportReconciliation(_M2Record):
    SCHEMA_ID: ClassVar[str] = SCHEMA_EXPORT_RECONCILIATION
    LABEL: ClassVar[str] = "export reconciliation"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "reservation_id",
        "verified",
        "state",
        "source_mutated",
        "private_ipc_exported",
        "partial_export",
        "note",
    )

    reservation_id: str
    verified: bool
    state: str
    source_mutated: bool
    private_ipc_exported: bool
    partial_export: bool
    note: str
    record_fingerprint: Fingerprint

    @classmethod
    def create(cls, **values: Any) -> "ExportReconciliation":
        return cls._new(**values)

    def _validate_fields(self) -> None:
        _require_text(self.reservation_id, "reservation_id", max_bytes=256)
        _require_text(self.state, "state", max_bytes=64)
        _require_text(self.note, "note", max_bytes=2048)
        if self.state not in EXPORT_STATES:
            raise ObservationError(f"invalid export state {self.state}")
        for name in ("verified", "source_mutated", "private_ipc_exported", "partial_export"):
            if not isinstance(getattr(self, name), bool):
                raise ObservationError(f"{name} must be a boolean")


M2_PRIVATE_WORKSPACE_SCHEMAS = {
    record_type.SCHEMA_ID: m2_schema_descriptor(
        record_type.SCHEMA_ID,
        record_type.__name__,
        ("schema_id", "schema_version") + record_type.FIELDS + ("record_fingerprint",),
    )
    for record_type in (
        SourceSnapshotIdentity,
        PrivateExecutionViewIdentity,
        ProposedExportChangeSet,
        ExportReservation,
        ExportReceipt,
        ExportReconciliation,
    )
}
for _descriptor in M2_PRIVATE_WORKSPACE_SCHEMAS.values():
    object.__setattr__(_descriptor, "owning_module", "admissible.paired_runner.private_workspace")


def _materialize_copy_to_fd(source_fd: int, dest_fd: int) -> None:
    for relative, info in _walk_tree(source_fd):
        kind = _entry_kind(info.st_mode)
        if _is_ipc_or_special(kind):
            raise PrivateWorkspaceError("source_contains_special_inode", f"{kind}:{relative}")
        if kind == "directory":
            parent_fd, leaf = _open_parent(dest_fd, relative)
            try:
                os.mkdir(leaf, PRIVATE_DIR_MODE, dir_fd=parent_fd)
            except FileExistsError:
                pass
            finally:
                os.close(parent_fd)
        elif kind == "regular_file":
            src_parent, src_leaf = _open_parent(source_fd, relative)
            try:
                src_handle = os.open(src_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src_parent)
            finally:
                os.close(src_parent)
            try:
                dst_parent, dst_leaf = _open_parent(dest_fd, relative)
                try:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                    dst_handle = os.open(dst_leaf, flags, PRIVATE_FILE_MODE, dir_fd=dst_parent)
                    try:
                        while True:
                            chunk = os.read(src_handle, 1 << 20)
                            if not chunk:
                                break
                            offset = 0
                            while offset < len(chunk):
                                offset += os.write(dst_handle, chunk[offset:])
                        os.fchmod(dst_handle, PRIVATE_FILE_MODE)
                    finally:
                        os.close(dst_handle)
                finally:
                    os.close(dst_parent)
            finally:
                os.close(src_handle)
        elif kind == "symlink":
            src_parent, src_leaf = _open_parent(source_fd, relative)
            try:
                target = os.readlink(src_leaf, dir_fd=src_parent)
            finally:
                os.close(src_parent)
            if not _symlink_is_exportable(target):
                raise PrivateWorkspaceError("source_symlink_not_exportable", relative)
            dst_parent, dst_leaf = _open_parent(dest_fd, relative)
            try:
                os.symlink(target, dst_leaf, dir_fd=dst_parent)
            finally:
                os.close(dst_parent)
        else:
            raise PrivateWorkspaceError("source_contains_special_inode", f"{kind}:{relative}")


@dataclass
class PrivateExecutionView:
    """One private per-effect filesystem view retained by descriptor only."""

    helper: PrivateMountHelper
    source_snapshot: SourceSnapshotIdentity
    view_identity: PrivateExecutionViewIdentity
    _closed: bool = False
    #: M2-B43.  The last closure evidence, kept so a caller that must decide
    #: whether anything remains to clean up reads a fact rather than a flag.
    _closure: dict[str, Any] | None = None

    @property
    def view_fd(self) -> int:
        return self.helper.view_fd

    @property
    def view_root(self) -> Path:
        """Helper-internal staging path.  Not a host-reachable mutation target."""

        return Path(self.helper.staging_path)

    @classmethod
    def materialize(cls, source_root: Path, source_fd: int) -> "PrivateExecutionView":
        """Copy the authorized source into a private mount-namespace tmpfs."""

        info = os.fstat(source_fd)
        tree_sha, entry_count, total_bytes, specials = snapshot_tree_identity(source_fd)
        if specials:
            raise PrivateWorkspaceError("source_contains_special_inode", specials[0])
        snapshot = SourceSnapshotIdentity.create(
            source_root=str(Path(os.path.realpath(source_root))),
            device=info.st_dev,
            inode=info.st_ino,
            tree_sha256=tree_sha,
            entry_count=entry_count,
            total_regular_file_bytes=total_bytes,
            special_inode_count=0,
        )
        helper = PrivateMountHelper.start()
        try:
            _materialize_copy_to_fd(source_fd, helper.view_fd)
            view_info = os.fstat(helper.view_fd)
            view_sha, view_entries, _, view_specials = snapshot_tree_identity(helper.view_fd)
            if view_specials:
                raise PrivateWorkspaceError("private_view_contains_special_inode", view_specials[0])
            if view_sha != tree_sha:
                raise PrivateWorkspaceError("private_view_digest_mismatch", f"{view_sha}!={tree_sha}")
            if host_can_pathname_reach(helper.view_fd):
                raise PrivateWorkspaceError("private_view_host_pathname_reachable", helper.staging_path)
            identity = PrivateExecutionViewIdentity.create(
                view_root=helper.staging_path,
                device=view_info.st_dev,
                inode=view_info.st_ino,
                source_snapshot_fingerprint=snapshot.record_fingerprint,
                tree_sha256=view_sha,
                entry_count=view_entries,
                materialization_kind=MATERIALIZATION_KIND,
            )
            return cls(helper=helper, source_snapshot=snapshot, view_identity=identity)
        except BaseException as error:
            # M2-B48.  The closure evidence of a materialisation that failed is
            # the only record of a helper this controller forked and may not
            # have reaped.  Discarding it here -- which is what this path did --
            # dropped the retry handle at the exact moment it was needed, so the
            # evidence is carried on the refusal and the handle is retained by
            # the process registry rather than by this frame.
            closure = helper.close()
            if not closure.get("cleanup_complete"):
                try:
                    error.cleanup_evidence = dict(closure)  # type: ignore[attr-defined]
                    error.cleanup_registry_id = closure.get(  # type: ignore[attr-defined]
                        "cleanup_registry_id"
                    )
                except Exception:  # pragma: no cover - an exception that refuses attributes
                    pass
            raise

    def write_file(self, relative: str, data: bytes) -> None:
        parent_fd, leaf = _open_parent(self.view_fd, relative)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            handle = os.open(leaf, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
            try:
                offset = 0
                while offset < len(data):
                    offset += os.write(handle, data[offset:])
            finally:
                os.close(handle)
        finally:
            os.close(parent_fd)

    def mkfifo(self, relative: str) -> None:
        parent_fd, leaf = _open_parent(self.view_fd, relative)
        try:
            os.mkfifo(leaf, 0o600, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

    def host_pathname_reachable(self) -> bool:
        return host_can_pathname_reach(self.view_fd)

    def spawn_launcher(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        pass_fds: tuple[int, ...] = (),
        await_release: bool = False,
    ) -> SpawnedLauncher:
        return self.helper.spawn(argv, pass_fds=pass_fds, await_release=await_release)

    def source_mutated(self, source_fd: int) -> bool:
        tree_sha, _, _, _ = snapshot_tree_identity(source_fd)
        return tree_sha != self.source_snapshot.tree_sha256

    @property
    def cleanup_complete(self) -> bool:
        """Whether this view's helper is reaped, released, and settled."""

        return self.helper.cleanup_complete

    @property
    def registry_id(self) -> str | None:
        """The process cleanup-registry entry retaining this view (M2-B48)."""

        return self.helper.registry_id

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """The one retry protocol every retained cleanup handle answers (M2-B48)."""

        return self.close(deadline=deadline)

    def cleanup_evidence(self) -> dict[str, Any]:
        """The last closure document, without performing another closure."""

        return self.helper.cleanup_evidence()

    def close(self, *, deadline: Deadline | None = None) -> dict[str, Any]:
        """Close the view and report what the shutdown left undone (M2-B43).

        Idempotent once the cleanup is complete, and retryable until it is: a
        view whose helper survived its deadline still owns a process this
        controller must reap, and a ``_closed`` flag that swallowed the retry is
        what made that unreachable.

        M2-B48.  The evidence returned here names the process registry entry
        that retains the retry handle, so a caller that lets this object go out
        of scope has not thereby lost the cleanup.
        """

        self._closed = True
        # The helper owns the idempotence: a completed lifecycle answers
        # immediately and performs nothing, and an incomplete one retries.  The
        # view keeps the answer rather than deciding it, so the two can never
        # disagree about whether anything is left to do.
        self._closure = self.helper.close(deadline=deadline)
        return dict(self._closure)


def _tree_map(root_fd: int) -> dict[str, tuple[str, str | None]]:
    mapping: dict[str, tuple[str, str | None]] = {}
    for relative, info in _walk_tree(root_fd):
        kind = _entry_kind(info.st_mode)
        if kind == "regular_file":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                sha, _ = _hash_regular_at(parent_fd, leaf)
            finally:
                os.close(parent_fd)
            mapping[relative] = (kind, sha)
        elif kind == "symlink":
            parent_fd, leaf = _open_parent(root_fd, relative)
            try:
                target = os.readlink(leaf, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            mapping[relative] = (kind, target)
        elif kind == "directory":
            mapping[relative] = (kind, None)
        else:
            mapping[relative] = (kind, None)
    return mapping


def compute_change_set(*, baseline_fd: int, private_fd: int) -> ProposedExportChangeSet:
    before = _tree_map(baseline_fd)
    after = _tree_map(private_fd)
    operations: list[str] = []
    paths: list[str] = []
    unsupported: list[str] = []

    for relative, (kind, _) in sorted(before.items()):
        if relative in after:
            continue
        if kind == "regular_file":
            operations.append("DELETE_REGULAR_FILE")
        elif kind == "directory":
            operations.append("DELETE_DIRECTORY")
        elif kind == "symlink":
            operations.append("DELETE_SYMLINK")
        else:
            unsupported.append(f"{kind}:{relative}")
            continue
        paths.append(relative)

    for relative, (kind, payload) in sorted(after.items()):
        if _is_ipc_or_special(kind):
            unsupported.append(f"{kind}:{relative}")
            continue
        previous = before.get(relative)
        if previous is None:
            if kind == "regular_file":
                operations.append("CREATE_REGULAR_FILE")
            elif kind == "directory":
                operations.append("CREATE_DIRECTORY")
            elif kind == "symlink":
                if payload is None or not _symlink_is_exportable(payload):
                    unsupported.append(f"symlink:{relative}")
                    continue
                operations.append("CREATE_SYMLINK")
            else:
                unsupported.append(f"{kind}:{relative}")
                continue
            paths.append(relative)
            continue
        prev_kind, prev_payload = previous
        if prev_kind == kind and prev_payload == payload:
            continue
        if kind == "regular_file" and prev_kind == "regular_file":
            operations.append("UPDATE_REGULAR_FILE")
            paths.append(relative)
        elif kind == "symlink" and prev_kind == "symlink":
            if payload is None or not _symlink_is_exportable(payload):
                unsupported.append(f"symlink:{relative}")
                continue
            operations.append("UPDATE_SYMLINK")
            paths.append(relative)
        else:
            unsupported.append(f"type_change:{relative}:{prev_kind}->{kind}")

    digest = hashlib.sha256()
    for operation, path in zip(operations, paths):
        digest.update(operation.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.encode("utf-8"))
        digest.update(b"\n")
    return ProposedExportChangeSet.create(
        change_count=len(operations),
        operations=tuple(operations),
        paths=tuple(paths),
        change_set_sha256=digest.hexdigest(),
        unsupported_inode_count=len(unsupported),
        unsupported_inodes=tuple(unsupported),
    )


def _complete_write(handle: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(handle, data[offset:])
        if written <= 0:
            raise PrivateWorkspaceError("short_write", str(offset))
        offset += written


def _fsync_dir(path: Path) -> None:
    handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def _durable_publish_json(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    """No-replace durable publish: temp write, fsync file, linkat EXCL, fsync dir."""

    directory.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    final = directory / name
    if final.exists():
        raise PrivateWorkspaceError("durable_replace_forbidden", name)
    temporary = directory / f".tmp-{os.getpid()}-{name}"
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, FILE_MODE)
    try:
        _complete_write(handle, raw)
        os.fsync(handle)
    finally:
        os.close(handle)
    try:
        os.link(temporary, final)
    except FileExistsError as error:
        raise PrivateWorkspaceError("durable_replace_forbidden", name) from error
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass
    _fsync_dir(directory)
    return final


def _durable_replace_json(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    """Replaceable progress document: write temp, fsync, rename, fsync dir."""

    directory.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = directory / f".tmp-{os.getpid()}-{name}"
    final = directory / name
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, FILE_MODE)
    try:
        _complete_write(handle, raw)
        os.fsync(handle)
    finally:
        os.close(handle)
    os.replace(temporary, final)
    _fsync_dir(directory)
    return final


def _path_state(root_fd: int, relative: str) -> dict[str, Any]:
    try:
        parent_fd, leaf = _open_parent(root_fd, relative)
    except OSError:
        return {"kind": "absent"}
    try:
        try:
            info = os.lstat(leaf, dir_fd=parent_fd)
        except FileNotFoundError:
            return {"kind": "absent"}
        kind = _entry_kind(info.st_mode)
        if kind == "regular_file":
            sha, size = _hash_regular_at(parent_fd, leaf)
            return {"kind": kind, "sha256": sha, "size": size}
        if kind == "symlink":
            return {"kind": kind, "target": os.readlink(leaf, dir_fd=parent_fd)}
        return {"kind": kind}
    finally:
        os.close(parent_fd)


def _build_operation_plan(
    *,
    source_fd: int,
    private_fd: int,
    change_set: ProposedExportChangeSet,
) -> list[dict[str, Any]]:
    before = _tree_map(source_fd)
    after = _tree_map(private_fd)
    plan: list[dict[str, Any]] = []
    paired = list(zip(change_set.operations, change_set.paths))
    deletes = [(op, path) for op, path in paired if op.startswith("DELETE_")]
    others = [(op, path) for op, path in paired if not op.startswith("DELETE_")]
    deletes.sort(key=lambda item: item[1].count("/"), reverse=True)
    others.sort(key=lambda item: item[1].count("/"))
    for index, (operation, relative) in enumerate(deletes + others):
        pre = _path_state(source_fd, relative)
        if operation.startswith("DELETE"):
            post = {"kind": "absent"}
        elif operation in {"CREATE_REGULAR_FILE", "UPDATE_REGULAR_FILE"}:
            payload = after.get(relative)
            post = {"kind": "regular_file", "sha256": None if payload is None else payload[1]}
        elif operation in {"CREATE_SYMLINK", "UPDATE_SYMLINK"}:
            payload = after.get(relative)
            post = {"kind": "symlink", "target": None if payload is None else payload[1]}
        elif operation == "CREATE_DIRECTORY":
            post = {"kind": "directory"}
        else:
            post = {"kind": "absent"}
        plan.append(
            {
                "index": index,
                "operation": operation,
                "path": relative,
                "expected_pre_state": pre,
                "intended_post_state": post,
            }
        )
    return plan


def _make_outcome(
    *,
    reservation_id: str,
    source_snapshot: SourceSnapshotIdentity,
    view_identity: PrivateExecutionViewIdentity,
    change_set: ProposedExportChangeSet,
    state: str,
    applied: int,
    refusal: str,
    source_mutated: bool,
    partial: bool,
    note: str,
) -> tuple[ExportReservation, ExportReceipt, ExportReconciliation]:
    # Typed reservation remains RESERVED at admit time; the receipt carries the
    # terminal state published after durable barriers.
    reservation = ExportReservation.create(
        reservation_id=reservation_id,
        source_snapshot_fingerprint=source_snapshot.record_fingerprint,
        private_view_fingerprint=view_identity.record_fingerprint,
        change_set_fingerprint=change_set.record_fingerprint,
        state="RESERVED",
    )
    receipt = ExportReceipt.create(
        reservation_id=reservation_id,
        applied_count=applied,
        state=state,
        refusal_code=refusal,
        change_set_fingerprint=change_set.record_fingerprint,
    )
    reconciliation = ExportReconciliation.create(
        reservation_id=reservation_id,
        verified=state == "APPLIED",
        state=state,
        source_mutated=source_mutated,
        private_ipc_exported=False,
        partial_export=partial,
        note=note,
    )
    return reservation, receipt, reconciliation


def apply_export(
    *,
    source_root_fd: int,
    private_fd: int,
    change_set: ProposedExportChangeSet,
    reservation_id: str,
    source_snapshot: SourceSnapshotIdentity,
    view_identity: PrivateExecutionViewIdentity,
    durable_root: Path | str,
    causal: dict[str, str] | None = None,
) -> tuple[ExportReservation, ExportReceipt, ExportReconciliation]:
    """Apply a validated change set through the durable transactional protocol."""

    durable = Path(durable_root)
    export_dir = durable / "export" / reservation_id
    causal = {
        "run_id": (causal or {}).get("run_id", "unknown"),
        "session_id": (causal or {}).get("session_id", "unknown"),
        "proposal_id": (causal or {}).get("proposal_id", "unknown"),
        "decision_id": (causal or {}).get("decision_id", "unknown"),
        "reservation_id": (causal or {}).get("reservation_id", reservation_id),
        "effect_id": (causal or {}).get("effect_id", reservation_id),
    }

    # Refuse automatic replay of an existing durable reservation.
    existing = recover_export(durable, reservation_id)
    if existing.get("state") not in {None, "ABSENT"}:
        state = "REFUSED_REPLAY" if existing.get("state") == "APPLIED" else "REFUSED_AMBIGUOUS"
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state=state,
            applied=int(existing.get("applied_count") or 0),
            refusal="export_reservation_already_durable",
            source_mutated=False,
            partial=bool(existing.get("partial_export")),
            note="export refused: durable reservation already exists; automatic replay is forbidden",
        )
        return reservation, receipt, reconciliation

    if change_set.unsupported_inode_count:
        plan = []
    else:
        plan = _build_operation_plan(source_fd=source_root_fd, private_fd=private_fd, change_set=change_set)

    intended_final = snapshot_tree_identity(private_fd)[0]
    reservation_doc = {
        "schema_id": SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION,
        "schema_version": M2_SCHEMA_VERSION,
        "export_protocol_version": EXPORT_PROTOCOL_VERSION,
        "reservation_id": reservation_id,
        "causal": causal,
        "source_snapshot": source_snapshot.to_dict(),
        "private_view": view_identity.to_dict(),
        "change_set": change_set.to_dict(),
        "operations": plan,
        "intended_final_tree_sha256": intended_final,
        "source_tree_sha256_at_reserve": source_snapshot.tree_sha256,
        "state": "RESERVED",
        "durability_barriers": [
            "1.write_temp_reservation",
            "2.fsync_reservation_file",
            "3.link_no_replace_into_export_dir",
            "4.fsync_export_dir",
            "5.per_op_revalidate_pre_state",
            "6.mutate",
            "7.fsync_mutated_file_or_parent",
            "8.append_journal_entry_fsync",
            "9.verify_final_tree",
            "10.publish_receipt_fsync",
            "11.publish_reconciliation_fsync",
        ],
    }

    # Durable reservation BEFORE any authorized-source mutation.
    _durable_publish_json(export_dir, "reservation.json", reservation_doc)
    _durable_replace_json(
        export_dir,
        "progress.json",
        {"reservation_id": reservation_id, "applied_count": 0, "next_index": 0, "entries": []},
    )

    typed_reservation = ExportReservation.create(
        reservation_id=reservation_id,
        source_snapshot_fingerprint=source_snapshot.record_fingerprint,
        private_view_fingerprint=view_identity.record_fingerprint,
        change_set_fingerprint=change_set.record_fingerprint,
        state="RESERVED",
    )

    if change_set.unsupported_inode_count:
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state="REFUSED_UNSUPPORTED_INODE",
            applied=0,
            refusal="unsupported_inode_in_private_view",
            source_mutated=False,
            partial=False,
            note="export refused: private view contains an unsupported inode type",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    current_sha, _, _, _ = snapshot_tree_identity(source_root_fd)
    if current_sha != source_snapshot.tree_sha256:
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state="REFUSED_SOURCE_MUTATED",
            applied=0,
            refusal="source_mutated_during_effect",
            source_mutated=True,
            partial=False,
            note="export refused: authorized source mutated between snapshot and export",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    applied = 0
    journal: list[dict[str, Any]] = []
    try:
        for item in plan:
            pre_now = _path_state(source_root_fd, item["path"])
            if pre_now != item["expected_pre_state"]:
                raise PrivateWorkspaceError(
                    "concurrent_source_mutation",
                    f"{item['path']}:{pre_now}!={item['expected_pre_state']}",
                )
            _apply_one(source_root_fd, private_fd, item["operation"], item["path"])
            # Durability barrier for the mutated parent directory.
            parent_fd, _leaf = _open_parent(source_root_fd, item["path"])
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            applied += 1
            journal.append({"index": item["index"], "path": item["path"], "operation": item["operation"], "status": "APPLIED"})
            _durable_replace_json(
                export_dir,
                "progress.json",
                {
                    "reservation_id": reservation_id,
                    "applied_count": applied,
                    "next_index": applied,
                    "entries": journal,
                },
            )
    except PrivateWorkspaceError as error:
        state = "REFUSED_CONCURRENT_MUTATION" if error.code == "concurrent_source_mutation" else (
            "REFUSED_PARTIAL" if applied else "REFUSED_CRASH_CLASSIFIABLE"
        )
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state=state,
            applied=applied,
            refusal=error.code,
            source_mutated=error.code in {"concurrent_source_mutation", "source_mutated_during_effect"},
            partial=applied > 0,
            note=f"export failed after {applied} operations: {error.code}",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    final_sha, _, _, _ = snapshot_tree_identity(source_root_fd)
    if final_sha != intended_final:
        reservation, receipt, reconciliation = _make_outcome(
            reservation_id=reservation_id,
            source_snapshot=source_snapshot,
            view_identity=view_identity,
            change_set=change_set,
            state="REFUSED_PARTIAL",
            applied=applied,
            refusal="final_tree_identity_mismatch",
            source_mutated=False,
            partial=True,
            note="export refused: final full-tree identity did not match the intended post-state",
        )
        _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
        _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
        return typed_reservation, receipt, reconciliation

    # Ensure the source root directory itself is durable before success.
    os.fsync(source_root_fd)
    reservation, receipt, reconciliation = _make_outcome(
        reservation_id=reservation_id,
        source_snapshot=source_snapshot,
        view_identity=view_identity,
        change_set=change_set,
        state="APPLIED",
        applied=applied,
        refusal="none",
        source_mutated=False,
        partial=False,
        note="trusted transactional export applied only validated regular-file, directory, and symlink changes",
    )
    _durable_publish_json(export_dir, "receipt.json", receipt.to_dict())
    _durable_publish_json(export_dir, "reconciliation.json", reconciliation.to_dict())
    return typed_reservation, receipt, reconciliation


def recover_export(durable_root: Path | str, reservation_id: str) -> dict[str, Any]:
    """Classify an export from durable records and filesystem state alone."""

    export_dir = Path(durable_root) / "export" / reservation_id
    reservation_path = export_dir / "reservation.json"
    if not reservation_path.exists():
        return {"state": "ABSENT", "reservation_id": reservation_id, "classifiable": True}
    try:
        reservation = json.loads(reservation_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "REFUSED_AMBIGUOUS", "reservation_id": reservation_id, "classifiable": True, "reason": "corrupt_reservation"}
    receipt_path = export_dir / "receipt.json"
    progress_path = export_dir / "progress.json"
    progress = {}
    if progress_path.exists():
        try:
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            progress = {"corrupt": True}
    if receipt_path.exists():
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {
                "state": "REFUSED_AMBIGUOUS",
                "reservation_id": reservation_id,
                "classifiable": True,
                "reason": "corrupt_receipt",
                "applied_count": progress.get("applied_count"),
            }
        return {
            "state": receipt.get("state"),
            "reservation_id": reservation_id,
            "classifiable": True,
            "applied_count": receipt.get("applied_count"),
            "refusal_code": receipt.get("refusal_code"),
            "partial_export": receipt.get("state") == "REFUSED_PARTIAL",
            "replay_forbidden": True,
            "reservation": reservation,
            "progress": progress,
        }
    applied = int(progress.get("applied_count") or 0)
    if applied == 0:
        return {
            "state": "REFUSED_CRASH_CLASSIFIABLE",
            "reservation_id": reservation_id,
            "classifiable": True,
            "applied_count": 0,
            "partial_export": False,
            "replay_forbidden": True,
            "reason": "reserved_without_receipt",
            "reservation": reservation,
            "progress": progress,
        }
    return {
        "state": "REFUSED_PARTIAL",
        "reservation_id": reservation_id,
        "classifiable": True,
        "applied_count": applied,
        "partial_export": True,
        "replay_forbidden": True,
        "reason": "partial_journal_without_receipt",
        "reservation": reservation,
        "progress": progress,
    }


def _apply_one(source_fd: int, private_fd: int, operation: str, relative: str) -> None:
    parent_fd, leaf = _open_parent(source_fd, relative)
    try:
        if operation in {"DELETE_REGULAR_FILE", "DELETE_SYMLINK"}:
            try:
                os.unlink(leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_delete_failed", f"{relative}:{error.errno}") from error
            return
        if operation == "DELETE_DIRECTORY":
            try:
                os.rmdir(leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_rmdir_failed", f"{relative}:{error.errno}") from error
            return
        if operation == "CREATE_DIRECTORY":
            try:
                os.mkdir(leaf, DIRECTORY_MODE, dir_fd=parent_fd)
            except FileExistsError:
                info = os.lstat(leaf, dir_fd=parent_fd)
                if not stat.S_ISDIR(info.st_mode):
                    raise PrivateWorkspaceError("export_mkdir_conflict", relative)
            except OSError as error:
                raise PrivateWorkspaceError("export_mkdir_failed", f"{relative}:{error.errno}") from error
            return
        if operation in {"CREATE_REGULAR_FILE", "UPDATE_REGULAR_FILE"}:
            _export_regular_file(source_fd, private_fd, relative, parent_fd, leaf, replace=operation.startswith("UPDATE"))
            return
        if operation in {"CREATE_SYMLINK", "UPDATE_SYMLINK"}:
            priv_parent, priv_leaf = _open_parent(private_fd, relative)
            try:
                target = os.readlink(priv_leaf, dir_fd=priv_parent)
            finally:
                os.close(priv_parent)
            if not _symlink_is_exportable(target):
                raise PrivateWorkspaceError("export_symlink_not_exportable", relative)
            if operation.startswith("UPDATE"):
                try:
                    os.unlink(leaf, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            try:
                os.symlink(target, leaf, dir_fd=parent_fd)
            except OSError as error:
                raise PrivateWorkspaceError("export_symlink_failed", f"{relative}:{error.errno}") from error
            return
        raise PrivateWorkspaceError("export_unknown_operation", operation)
    finally:
        os.close(parent_fd)


def _export_regular_file(
    source_fd: int,
    private_fd: int,
    relative: str,
    parent_fd: int,
    leaf: str,
    *,
    replace: bool,
) -> None:
    priv_parent, priv_leaf = _open_parent(private_fd, relative)
    try:
        src = os.open(priv_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=priv_parent)
    finally:
        os.close(priv_parent)
    try:
        info = os.fstat(src)
        if not stat.S_ISREG(info.st_mode):
            raise PrivateWorkspaceError("export_not_regular_file", relative)
        tmp_name = f".admissible-export-{os.getpid()}-{leaf}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        try:
            dst = os.open(tmp_name, flags, FILE_MODE, dir_fd=parent_fd)
        except OSError as error:
            raise PrivateWorkspaceError("export_temp_create_failed", f"{relative}:{error.errno}") from error
        try:
            while True:
                chunk = os.read(src, 1 << 20)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk):
                    offset += os.write(dst, chunk[offset:])
            os.fchmod(dst, FILE_MODE)
            os.fsync(dst)
        finally:
            os.close(dst)
        try:
            os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError as error:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
            raise PrivateWorkspaceError("export_replace_failed", f"{relative}:{error.errno}") from error
    finally:
        os.close(src)


def private_ipc_host_visible(source_root: Path, private_view: PrivateExecutionView) -> tuple[str, ...]:
    source_fd = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _, _, _, source_specials = snapshot_tree_identity(source_fd)
    finally:
        os.close(source_fd)
    _, _, _, private_specials = snapshot_tree_identity(private_view.view_fd)
    source_set = set(source_specials)
    return tuple(item for item in private_specials if item in source_set)


__all__ = [
    "CLEANUP_KIND_EFFECT_CGROUP",
    "CLEANUP_KIND_HELPER",
    "CLEANUP_KIND_VIEW",
    "CLEANUP_REGISTRY_CAPACITY",
    "CLEANUP_RETRY_NONE",
    "CLEANUP_RETRY_REAP",
    "CLEANUP_RETRY_REMOVE_CGROUP",
    "CLEANUP_RETRY_RELEASE",
    "CLEANUP_RETRY_SETTLE",
    "CleanupRegistrySaturated",
    "EXPORT_OPERATIONS",
    "EXPORT_PROTOCOL_VERSION",
    "EXPORT_STATES",
    "ExportReceipt",
    "ExportReconciliation",
    "ExportReservation",
    "MATERIALIZATION_KIND",
    "M2_PRIVATE_WORKSPACE_SCHEMAS",
    "PrivateExecutionView",
    "PrivateExecutionViewIdentity",
    "PrivateMountHelper",
    "PrivateWorkspaceError",
    "ProposedExportChangeSet",
    "SCHEMA_EXPORT_RECEIPT",
    "SCHEMA_EXPORT_RECONCILIATION",
    "SCHEMA_EXPORT_RESERVATION",
    "SCHEMA_PRIVATE_EXECUTION_VIEW_IDENTITY",
    "SCHEMA_PROPOSED_EXPORT_CHANGE_SET",
    "SCHEMA_SOURCE_SNAPSHOT_IDENTITY",
    "SCHEMA_TRANSACTIONAL_EXPORT_RESERVATION",
    "SourceSnapshotIdentity",
    "SpawnedLauncher",
    "CANONICAL_RESULT_RETENTION",
    "CANONICAL_UNPUBLISHED_CLAIMED",
    "CANONICAL_UNPUBLISHED_NOT_REACHED",
    "CANONICAL_UNPUBLISHED_THREW",
    "CleanupReservationRefused",
    "DRAIN_STATES",
    "DRAIN_STATES_PROVING_DISCHARGE",
    "DRAIN_STATE_ATTEMPTED",
    "DRAIN_STATE_DISCHARGED_BY_CANONICAL",
    "DRAIN_STATE_RESOURCE_DISCHARGED",
    "DRAIN_STATE_RETAINED_PENDING_CANONICAL",
    "DRAIN_STATE_RETAINED_UNATTEMPTED",
    "DRAIN_STATE_UNRESOLVED",
    "DRAIN_UNATTEMPTED_ALIAS",
    "DRAIN_UNATTEMPTED_BUDGET_EXHAUSTED",
    "DRAIN_UNATTEMPTED_CANONICAL_UNRESOLVED",
    "DRAIN_UNATTEMPTED_RESOURCE_DISCHARGED",
    "DrainEvidenceContradiction",
    "RESERVATION_CONSUMED",
    "RESERVATION_REFUSED_ALREADY_CONSUMED",
    "RESERVATION_REFUSED_ALREADY_RELEASED",
    "RESERVATION_REFUSED_FOREIGN_PID",
    "RESERVATION_REFUSED_FOREIGN_REGISTRY",
    "RESERVATION_REFUSED_FOREIGN_TYPE",
    "RESERVATION_REFUSED_NOT_IN_TABLE",
    "RESERVATION_REFUSED_NOT_THE_SAME_OBJECT",
    "RESERVATION_REFUSED_STALE_EPOCH",
    "RESERVATION_RELEASED",
    "RESERVATION_RESERVED",
    "apply_export",
    "cleanup_drain_ledger",
    "cleanup_registry_evidence",
    "compute_change_set",
    "drain_incomplete_cleanups",
    "host_can_pathname_reach",
    "incomplete_cleanups",
    "private_ipc_host_visible",
    "published_canonical_results",
    "recover_export",
    "retry_unsettled_failed_starts",
    "snapshot_tree_identity",
    "unsettled_failed_starts",
]
