"""Per-command resource containment for the untrusted process domain.

A private PID namespace is a *naming* boundary, not a quota.  Milestone 2's
capsule could therefore be entered by a command that forked without bound,
allocated without bound, opened descriptors without bound, or spun the CPU until
the wall-clock timeout expired -- every one of which reaches the host before the
timeout is the thing that stops it.  The audit recorded that as a disclosed
limitation; a substrate that calls its effect process untrusted cannot keep it.

Two layers are applied, in this order of preference:

``CGROUP_V2_AND_RLIMIT``
    A per-effect cgroup v2 subtree, when the host actually delegates one, bounds
    the whole process domain in aggregate: ``pids.max`` and ``memory.max`` apply
    to every descendant together rather than to each process individually.

``RLIMIT``
    ``setrlimit`` applied inside the capsule immediately before ``execv``.  This
    layer is *always* applied and is physically probed at readiness, so a host
    that cannot deliver it refuses before any effect rather than running the
    command unbounded.

Neither layer is optional and neither is silent.  The effective bounds and the
mechanism that actually enforced them are reported by the in-capsule init in its
status document, so the durable observation records what the kernel did rather
than what the controller intended.

M2-B25 -- cgroup topology
-------------------------

An earlier readiness probe here proved only that an empty child directory could
be created and removed inside the delegated cgroup.  That is not the question.
cgroup v2 forbids a cgroup from holding processes *and* distributing controllers
to its children (the "no internal process" constraint), so a delegated service
cgroup that still contains the trusted controller can never enable ``memory`` or
``pids`` for a per-effect child -- and the first real ``EffectCgroup`` write
fails with ``EACCES`` long after readiness said ``available``.

The topology this module now bootstraps is therefore::

    delegated service cgroup                 <- the effect parent
    |-- admissible-manager-<pid>             <- trusted manager leaf
    |   `-- the paired-runner controller process
    `-- admissible-effect-<label>            <- one sibling per effect
        `-- the gated launcher / command process tree

The controller moves *itself* out of the delegated parent into the manager leaf,
proves the parent is then unpopulated, enables ``+memory +pids`` on the parent,
and reads the activation back from the kernel.  Only then can a sibling effect
cgroup carry real ``pids.max`` and ``memory.max`` values.  Readiness performs
that whole sequence -- including a real probe effect with a limit write and an
exact readback -- so readiness and execution can no longer disagree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
import ctypes.util
import errno
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any


#: Enforcement mechanisms, strongest first.
MECHANISM_CGROUP_AND_RLIMIT = "CGROUP_V2_AND_RLIMIT"
MECHANISM_RLIMIT = "RLIMIT"
MECHANISM_NONE = "NONE"

CONTAINMENT_MECHANISMS = (MECHANISM_CGROUP_AND_RLIMIT, MECHANISM_RLIMIT, MECHANISM_NONE)

#: The unified cgroup v2 hierarchy mount point on a conforming Linux host.
CGROUP_V2_ROOT = Path("/sys/fs/cgroup")

#: Default per-command bounds.  They are deliberately fixed constants at this
#: milestone: a per-request bound would be a policy input, and this substrate
#: contains no policy.  Each is large enough for an ordinary build or test
#: command and small enough that an unbounded consumer is stopped well before it
#: can disturb the host.
DEFAULT_MAX_PROCESSES = 64
DEFAULT_MAX_ADDRESS_SPACE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_OPEN_FILES = 256
DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024
#: How much CPU time a command may burn beyond its own wall-clock request.  A
#: command may legitimately use every second it asked for on several cores, so
#: the CPU bound is derived from the request rather than fixed.
CPU_SECONDS_HEADROOM = 30
#: Core dumps are refused outright: a dump of an untrusted process is an
#: unbounded write into the workspace that nothing proposed.
CORE_DUMP_BYTES = 0


class ResourceContainmentUnavailable(RuntimeError):
    """The required bounds cannot be enforced, so no effect may be attempted.

    ``release_state`` and ``cleanup_evidence`` are populated when the refusal
    happened around the trusted gate (M2-B30).  They are what the caller uses to
    decide what it may truthfully claim about whether the command ran, and they
    are never inferred from the fact that an exception was raised.
    """

    def __init__(
        self,
        message: str,
        *,
        release_state: str | None = None,
        cleanup_evidence: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.release_state = release_state
        self.cleanup_evidence = dict(cleanup_evidence or {})


@dataclass(frozen=True)
class ResourceBounds:
    """The exact bounds one capsuled command runs under."""

    max_processes: int
    max_address_space_bytes: int
    max_cpu_seconds: int
    max_open_files: int
    max_file_size_bytes: int
    core_dump_bytes: int

    @classmethod
    def for_timeout(cls, timeout_ms: int) -> "ResourceBounds":
        seconds = max(1, int(math.ceil(max(0, timeout_ms) / 1000.0)))
        return cls(
            max_processes=DEFAULT_MAX_PROCESSES,
            max_address_space_bytes=DEFAULT_MAX_ADDRESS_SPACE_BYTES,
            max_cpu_seconds=seconds + CPU_SECONDS_HEADROOM,
            max_open_files=DEFAULT_MAX_OPEN_FILES,
            max_file_size_bytes=DEFAULT_MAX_FILE_SIZE_BYTES,
            core_dump_bytes=CORE_DUMP_BYTES,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_processes": self.max_processes,
            "max_address_space_bytes": self.max_address_space_bytes,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_open_files": self.max_open_files,
            "max_file_size_bytes": self.max_file_size_bytes,
            "core_dump_bytes": self.core_dump_bytes,
        }

    def encode(self) -> str:
        """The compact form handed to the in-capsule init on its command line.

        The init runs inside the capsule, where this package is not mounted, so
        it cannot import these constants.  They travel as one canonical JSON
        argument instead, and the init echoes back what it actually applied.
        """

        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def decode(cls, raw: str) -> "ResourceBounds":
        payload = json.loads(raw)
        return cls(
            max_processes=int(payload["max_processes"]),
            max_address_space_bytes=int(payload["max_address_space_bytes"]),
            max_cpu_seconds=int(payload["max_cpu_seconds"]),
            max_open_files=int(payload["max_open_files"]),
            max_file_size_bytes=int(payload["max_file_size_bytes"]),
            core_dump_bytes=int(payload["core_dump_bytes"]),
        )


# --- cgroup v2 ---------------------------------------------------------------

#: Linux cgroup2 filesystem magic (``include/uapi/linux/magic.h``).
CGROUP2_SUPER_MAGIC = 0x63677270

#: The controllers a per-effect cgroup must actually carry.
REQUIRED_CONTROLLERS = ("memory", "pids")

#: The trusted manager leaf that holds the controller process.  Effects are
#: created as *siblings* of this leaf, never beneath it.
MANAGER_LEAF_PREFIX = "admissible-manager"
#: One sibling cgroup per effect.
EFFECT_PREFIX = "admissible-effect-"
#: The transient cgroup the readiness probe creates and removes.
PROBE_PREFIX = "admissible-probe-"

#: A label may name a directory and nothing else.
_SAFE_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,96}\Z")

#: Classified topology outcomes.  ``TOPOLOGY_INITIALIZED`` is the only success.
TOPOLOGY_INITIALIZED = "INITIALIZED"
TOPOLOGY_NO_UNIFIED_CGROUP_V2 = "NO_UNIFIED_CGROUP_V2"
TOPOLOGY_CGROUP2_NOT_MOUNTED = "CGROUP2_NOT_MOUNTED"
TOPOLOGY_DELEGATED_PATH_MISSING = "DELEGATED_PATH_MISSING"
TOPOLOGY_DELEGATED_PATH_NOT_CGROUP2 = "DELEGATED_PATH_NOT_CGROUP2"
TOPOLOGY_CONTROLLERS_UNREADABLE = "CONTROLLERS_UNREADABLE"
TOPOLOGY_MISSING_CONTROLLERS = "MISSING_CONTROLLERS"
TOPOLOGY_MANAGER_COLLISION = "MANAGER_LEAF_COLLISION"
TOPOLOGY_MANAGER_CREATE_FAILED = "MANAGER_LEAF_CREATE_FAILED"
TOPOLOGY_CONTROLLER_MOVE_FAILED = "CONTROLLER_MOVE_FAILED"
TOPOLOGY_CONTROLLER_MOVE_NOT_OBSERVED = "CONTROLLER_MOVE_NOT_OBSERVED"
TOPOLOGY_PARENT_STILL_POPULATED = "PARENT_STILL_POPULATED"
TOPOLOGY_SUBTREE_CONTROL_WRITE_FAILED = "SUBTREE_CONTROL_WRITE_FAILED"
TOPOLOGY_SUBTREE_CONTROL_UNREADABLE = "SUBTREE_CONTROL_UNREADABLE"
TOPOLOGY_CONTROLLER_READBACK_MISMATCH = "CONTROLLER_READBACK_MISMATCH"
TOPOLOGY_EFFECT_CREATE_FAILED = "EFFECT_CREATE_FAILED"
TOPOLOGY_EFFECT_COLLISION = "EFFECT_COLLISION"
TOPOLOGY_INVALID_LABEL = "INVALID_LABEL"
TOPOLOGY_LIMIT_WRITE_FAILED = "LIMIT_WRITE_FAILED"
TOPOLOGY_LIMIT_READBACK_MISMATCH = "LIMIT_READBACK_MISMATCH"
TOPOLOGY_STALE_CACHED_TOPOLOGY = "STALE_CACHED_TOPOLOGY"
TOPOLOGY_NOT_INITIALIZED = "TOPOLOGY_NOT_INITIALIZED"
#: M2-B28 -- probe cleanup outcomes.  A probe that cannot be proven gone is
#: never reported as ``available``, and is never described as "removed".
TOPOLOGY_PROBE_NOT_EMPTY = "PROBE_NOT_EMPTY"
TOPOLOGY_PROBE_CLEANUP_FAILED = "PROBE_CLEANUP_FAILED"
TOPOLOGY_PROBE_RESIDUAL_PATH = "PROBE_RESIDUAL_PATH"
TOPOLOGY_PROBE_DISAPPEARED = "PROBE_DISAPPEARED"
#: M2-B35 -- a membership read that failed is never an observation of emptiness.
TOPOLOGY_MEMBERSHIP_UNREADABLE = "CGROUP_MEMBERSHIP_UNREADABLE"
TOPOLOGY_MEMBERSHIP_MALFORMED = "CGROUP_MEMBERSHIP_MALFORMED"
TOPOLOGY_PROBE_MEMBERSHIP_UNREADABLE = "PROBE_MEMBERSHIP_UNREADABLE"

TOPOLOGY_CODES = (
    TOPOLOGY_INITIALIZED,
    TOPOLOGY_NO_UNIFIED_CGROUP_V2,
    TOPOLOGY_CGROUP2_NOT_MOUNTED,
    TOPOLOGY_DELEGATED_PATH_MISSING,
    TOPOLOGY_DELEGATED_PATH_NOT_CGROUP2,
    TOPOLOGY_CONTROLLERS_UNREADABLE,
    TOPOLOGY_MISSING_CONTROLLERS,
    TOPOLOGY_MANAGER_COLLISION,
    TOPOLOGY_MANAGER_CREATE_FAILED,
    TOPOLOGY_CONTROLLER_MOVE_FAILED,
    TOPOLOGY_CONTROLLER_MOVE_NOT_OBSERVED,
    TOPOLOGY_PARENT_STILL_POPULATED,
    TOPOLOGY_SUBTREE_CONTROL_WRITE_FAILED,
    TOPOLOGY_SUBTREE_CONTROL_UNREADABLE,
    TOPOLOGY_CONTROLLER_READBACK_MISMATCH,
    TOPOLOGY_EFFECT_CREATE_FAILED,
    TOPOLOGY_EFFECT_COLLISION,
    TOPOLOGY_INVALID_LABEL,
    TOPOLOGY_LIMIT_WRITE_FAILED,
    TOPOLOGY_LIMIT_READBACK_MISMATCH,
    TOPOLOGY_STALE_CACHED_TOPOLOGY,
    TOPOLOGY_NOT_INITIALIZED,
    TOPOLOGY_PROBE_NOT_EMPTY,
    TOPOLOGY_PROBE_CLEANUP_FAILED,
    TOPOLOGY_PROBE_RESIDUAL_PATH,
    TOPOLOGY_PROBE_DISAPPEARED,
    TOPOLOGY_MEMBERSHIP_UNREADABLE,
    TOPOLOGY_MEMBERSHIP_MALFORMED,
    TOPOLOGY_PROBE_MEMBERSHIP_UNREADABLE,
)


def _membership_code(membership: "CgroupMembership") -> str:
    return TOPOLOGY_MEMBERSHIP_MALFORMED if membership.malformed else TOPOLOGY_MEMBERSHIP_UNREADABLE


class _Statfs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_ulong * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


def statfs_f_type(path: Path | str) -> int | None:
    """The filesystem magic of ``path``, or ``None`` when it cannot be read.

    This is the single place that answers "is this really cgroupfs?".  An
    ordinary directory a unit test planted in ``/tmp`` reports ``TMPFS_MAGIC``
    and therefore never counts as kernel evidence.
    """

    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        buffer = _Statfs()
        if libc.statfs(os.fsencode(str(path)), ctypes.byref(buffer)) != 0:
            return None
        return int(buffer.f_type)
    except Exception:  # pragma: no cover - no libc statfs on this platform
        return None


def is_cgroup2_filesystem(path: Path | str) -> bool:
    """Whether ``path`` lives on a real cgroup2 mount."""

    return statfs_f_type(path) == CGROUP2_SUPER_MAGIC


def _errno_name(error: OSError) -> str:
    return errno.errorcode.get(error.errno, str(error.errno))


def _read_control(path: Path) -> tuple[str | None, str | None]:
    """Read one cgroup control file.  Returns ``(text, error_code)``."""

    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", "replace"), None
    except OSError as error:
        return None, _errno_name(error)


def _write_control(path: Path, payload: str) -> str | None:
    """Write one cgroup control file completely.  Returns an error code or ``None``.

    cgroup control files reject partial writes rather than buffering them, so a
    short write is a real failure and is classified as one instead of being
    retried into a different value.
    """

    data = payload.encode("utf-8")
    try:
        # ``O_CREAT`` is a no-op against cgroupfs, where the kernel creates every
        # interface file with the cgroup itself and refuses new ones outright.  It
        # exists so the deterministic fault tests can drive this exact function
        # against a constructed tree; it cannot manufacture kernel evidence,
        # because availability and membership are decided by the cgroup2 magic
        # check and the readback, never by a file having been writable.
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
    except OSError as error:
        return _errno_name(error)
    try:
        written = os.write(handle, data)
    except OSError as error:
        return _errno_name(error)
    finally:
        try:
            os.close(handle)
        except OSError:  # pragma: no cover
            pass
    if written != len(data):
        return f"SHORT_WRITE:{written}/{len(data)}"
    return None


# --- M2-B35: membership is a typed observation, never a bare set --------------
#
# ``_members_of`` used to map an unreadable ``cgroup.procs`` to ``set()``.  That
# made two opposite facts identical: "the kernel says this cgroup is empty" and
# "this controller could not read this cgroup at all".  Every security-relevant
# decision downstream -- is the delegated parent depopulated, did the controller
# land in its manager leaf, is the probe safe to remove, is the effect cgroup
# empty before attach, did the launcher actually join it, is the domain
# quiescent, may this cgroup be removed -- is a decision about emptiness, and
# each of them silently accepted a failed read as a positive answer.
#
# The typed result below carries the read outcome, the parsed PIDs, the exact
# path, the errno classification, and any malformed content, so a caller must
# say which of the two facts it is acting on.


class CgroupMembershipUnreadable(RuntimeError):
    """A cgroup membership read failed and no emptiness may be inferred."""

    def __init__(self, membership: "CgroupMembership") -> None:
        super().__init__(membership.refusal_detail())
        self.membership = membership


@dataclass(frozen=True)
class CgroupMembership:
    """One observation of one ``cgroup.procs`` file.

    ``opaque_member_count`` deserves its own field.  The kernel renders each
    member in the *reader's* PID namespace and prints ``0`` for a member that
    namespace cannot name.  A ``0`` is therefore neither a PID nor noise: it is
    a live member this controller may not address.  Folding it into ``pids``
    would invent a process; discarding it would report a populated cgroup as
    empty.  It is counted separately and it defeats emptiness.
    """

    path: str
    read_ok: bool
    pids: tuple[int, ...] = ()
    error_code: str | None = None
    malformed: bool = False
    malformed_detail: str = ""
    opaque_member_count: int = 0

    @property
    def usable(self) -> bool:
        """Whether this observation may be used to decide anything at all."""

        return self.read_ok and not self.malformed

    @property
    def observed_empty(self) -> bool:
        """Whether the kernel positively reported no members of any kind."""

        return self.usable and not self.pids and not self.opaque_member_count

    @property
    def observed_populated(self) -> bool:
        return self.usable and bool(self.pids or self.opaque_member_count)

    @property
    def fully_addressable(self) -> bool:
        """Whether every member can be named, and therefore signalled, here."""

        return self.usable and self.opaque_member_count == 0

    def contains(self, pid: int) -> bool:
        return self.usable and pid in self.pids

    def refusal_detail(self) -> str:
        if self.malformed:
            return f"{self.path}/cgroup.procs holds unparseable content: {self.malformed_detail}"
        if not self.read_ok:
            return f"{self.path}/cgroup.procs is unreadable: {self.error_code}"
        if self.opaque_member_count:
            return (
                f"{self.path}/cgroup.procs lists {self.opaque_member_count} member(s) that this "
                "PID namespace cannot name"
            )
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "read_ok": self.read_ok,
            "pids": list(self.pids),
            "error_code": self.error_code,
            "malformed": self.malformed,
            "malformed_detail": self.malformed_detail,
            "opaque_member_count": self.opaque_member_count,
            "usable": self.usable,
            "observed_empty": self.observed_empty,
            "fully_addressable": self.fully_addressable,
        }


def read_cgroup_members(cgroup: Path | str) -> CgroupMembership:
    """Read one ``cgroup.procs`` and report what was actually observed.

    An unreadable file and a readable file holding content that is not a list of
    decimal PIDs are both refusals.  Neither is ever an empty set.
    """

    path = Path(cgroup)
    raw, error = _read_control(path / "cgroup.procs")
    if raw is None:
        return CgroupMembership(str(path), read_ok=False, error_code=error)
    pids: list[int] = []
    opaque = 0
    rejected: list[str] = []
    for token in raw.split():
        if not token.isdigit():
            rejected.append(token[:32])
        elif int(token) > 0:
            pids.append(int(token))
        else:
            opaque += 1
    if rejected:
        return CgroupMembership(
            str(path),
            read_ok=True,
            pids=tuple(sorted(pids)),
            malformed=True,
            malformed_detail=f"unparseable tokens {sorted(rejected)}",
            opaque_member_count=opaque,
        )
    return CgroupMembership(
        str(path), read_ok=True, pids=tuple(sorted(pids)), opaque_member_count=opaque
    )


def _enabled_controllers(cgroup: Path) -> tuple[tuple[str, ...] | None, str | None]:
    raw, error = _read_control(cgroup / "cgroup.subtree_control")
    if raw is None:
        return None, error
    # The kernel reports bare controller names.  A leading ``+`` can only ever
    # be the text this module wrote, so normalising it keeps the comparison
    # about whether a controller activated rather than about spelling; it can
    # never mask a controller the kernel declined to enable.
    return tuple(token.lstrip("+") for token in raw.split()), None


def _parse_limit(raw: str | None) -> int | None:
    """Interpret a numeric cgroup limit.  ``max`` is never a finite bound."""

    if raw is None:
        return None
    token = raw.strip()
    if not token or token == "max":
        return None
    try:
        return int(token)
    except ValueError:
        return None


def _own_unified_cgroup() -> str | None:
    """The unified-hierarchy path of this process, or ``None``."""

    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(":", 2)
                # The unified hierarchy is the entry with an empty controller
                # list, which is how cgroup v2 identifies itself in this file.
                if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
                    return parts[2]
    except OSError:
        return None
    return None


def _pid_unified_cgroup(pid: int) -> str | None:
    """The unified-hierarchy path of ``pid`` as corroborating evidence."""

    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(":", 2)
                if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
                    return parts[2]
    except OSError:
        return None
    return None


@dataclass(frozen=True)
class CgroupTopology:
    """The trusted controller topology this process actually bootstrapped.

    ``initialized`` is true only when every transition below was observed from
    kernel state: the manager leaf exists, the controller is in it, the
    delegated parent is unpopulated, and ``memory`` and ``pids`` were read back
    from the parent's ``cgroup.subtree_control``.
    """

    initialized: bool
    code: str
    detail: str
    unified_root: str | None = None
    unified_cgroup: str | None = None
    effect_parent: str | None = None
    manager_leaf: str | None = None
    available_controllers: tuple[str, ...] = ()
    enabled_controllers: tuple[str, ...] = ()
    owner_pid: int | None = None
    manager_leaf_created: bool = False
    #: ``dev:ino`` of the two directories, so a path that was removed and
    #: recreated under the same name is rejected rather than reused (M2-B29).
    effect_parent_identity: str | None = None
    manager_leaf_identity: str | None = None
    #: The full unified-hierarchy path the controller must still report.
    owner_unified_path: str | None = None
    #: Whether cgroup2 evidence was required when this topology was derived.
    cgroup2_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "initialized": self.initialized,
            "code": self.code,
            "detail": self.detail,
            "unified_root": self.unified_root,
            "unified_cgroup": self.unified_cgroup,
            "effect_parent": self.effect_parent,
            "manager_leaf": self.manager_leaf,
            "available_controllers": list(self.available_controllers),
            "enabled_controllers": list(self.enabled_controllers),
            "owner_pid": self.owner_pid,
            "manager_leaf_created": self.manager_leaf_created,
            "effect_parent_identity": self.effect_parent_identity,
            "manager_leaf_identity": self.manager_leaf_identity,
            "owner_unified_path": self.owner_unified_path,
            "cgroup2_required": self.cgroup2_required,
        }


def _failed(code: str, detail: str, **fields: Any) -> CgroupTopology:
    return CgroupTopology(initialized=False, code=code, detail=detail, **fields)


_TOPOLOGY_LOCK = threading.RLock()
_TOPOLOGY: CgroupTopology | None = None


def _directory_identity(path: Path) -> str | None:
    """``dev:ino`` of a directory, or ``None`` when it is not a directory.

    A cgroup that was removed and recreated under the same name is a *different*
    cgroup with different controller state.  Comparing names alone accepts the
    replacement; comparing identity refuses it.
    """

    try:
        info = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    return f"{info.st_dev}:{info.st_ino}"


def _unified_path_of(root: Path | str, directory: Path | str) -> str:
    """The unified-hierarchy path ``directory`` corresponds to under ``root``."""

    relative = os.path.relpath(str(directory), str(root))
    if relative in (".", ""):
        return "/"
    return "/" + relative.replace(os.sep, "/")


def _topology_is_still_true(topology: CgroupTopology) -> str | None:
    """Re-derive a cached topology from kernel state.  Returns a refusal detail.

    M2-B29.  Every physically material property that made the cached answer true
    is checked again here, because the cached Python object is a promise about
    the kernel and the kernel is free to have changed.  Name equality, path
    existence, and membership are not sufficient: a replaced directory, a parent
    that regained a process, or a controller the kernel stopped distributing all
    invalidate the promise while leaving those three checks green.
    """

    if topology.owner_pid != os.getpid():
        # A cache inherited across fork() describes the parent's topology.
        return f"cache_pid={topology.owner_pid} current_pid={os.getpid()}"
    if topology.manager_leaf is None or topology.effect_parent is None:
        return "cached topology has no manager leaf"
    if topology.unified_root is None:
        return "cached topology has no unified root"

    root = Path(topology.unified_root)
    manager = Path(topology.manager_leaf)
    parent = Path(topology.effect_parent)

    manager_identity = _directory_identity(manager)
    if manager_identity is None:
        return f"the manager leaf {manager} no longer exists"
    parent_identity = _directory_identity(parent)
    if parent_identity is None:
        return f"the effect parent {parent} no longer exists"
    if topology.manager_leaf_identity is not None and manager_identity != topology.manager_leaf_identity:
        return (
            f"the manager leaf {manager} is now {manager_identity}, not the cached "
            f"{topology.manager_leaf_identity}; it was replaced"
        )
    if topology.effect_parent_identity is not None and parent_identity != topology.effect_parent_identity:
        return (
            f"the effect parent {parent} is now {parent_identity}, not the cached "
            f"{topology.effect_parent_identity}; it was replaced"
        )
    if manager.parent != parent:
        return f"the manager leaf {manager} is no longer a child of {parent}"

    members = read_cgroup_members(manager)
    if not members.usable:
        # M2-B35.  "I could not read the manager leaf" is not "the controller is
        # in the manager leaf", and it is not "the controller is not".  It is a
        # refusal to reuse a cached promise that can no longer be checked.
        return members.refusal_detail()
    if os.getpid() not in members.pids:
        return f"the controller is no longer a member of {manager}"

    if topology.cgroup2_required:
        if not is_cgroup2_filesystem(parent):
            return f"{parent} is no longer on a cgroup2 filesystem"
        if not is_cgroup2_filesystem(manager):
            return f"{manager} is no longer on a cgroup2 filesystem"
        # The full unified path, resolved against the real mount -- not the
        # basename, which two unrelated leaves can share.
        expected = topology.owner_unified_path or _unified_path_of(root, manager)
        current = _own_unified_cgroup()
        if current is None:
            return "the controller no longer reports a cgroup v2 unified hierarchy"
        if current != expected:
            return f"the controller unified cgroup is now {current}, not {expected}"

    residual = read_cgroup_members(parent)
    if not residual.usable:
        # The reproduction the audit asks for: ``parent/cgroup.procs -> EACCES``
        # must refuse.  Parent depopulation is the whole basis of the delegated
        # topology, so a parent whose membership cannot be read invalidates the
        # cached promise rather than passing as empty.
        return residual.refusal_detail()
    if residual.observed_populated:
        # A populated parent cannot distribute controllers; the promise is dead
        # whether or not the subtree_control file still reads back.  A member
        # this PID namespace cannot name still populates the parent.
        return (
            f"the delegated effect parent {parent} now holds {list(residual.pids)}"
            + (f" plus {residual.opaque_member_count} unnameable member(s)" if residual.opaque_member_count else "")
        )

    raw_controllers, control_error = _read_control(parent / "cgroup.controllers")
    if raw_controllers is None:
        return f"{parent}/cgroup.controllers is unreadable: {control_error}"
    available = tuple(raw_controllers.split())
    missing = [name for name in REQUIRED_CONTROLLERS if name not in available]
    if missing:
        return f"{parent}/cgroup.controllers no longer offers {missing}"

    enabled, enabled_error = _enabled_controllers(parent)
    if enabled is None:
        return f"{parent}/cgroup.subtree_control is unreadable: {enabled_error}"
    absent = [name for name in REQUIRED_CONTROLLERS if name not in enabled]
    if absent:
        return f"{parent}/cgroup.subtree_control no longer enables {absent}"

    if topology.enabled_controllers:
        regressed = [name for name in topology.enabled_controllers if name not in enabled]
        if regressed:
            return f"the cached enabled controllers {regressed} are no longer enabled on {parent}"
    if topology.available_controllers:
        gone = [name for name in topology.available_controllers if name not in available]
        if gone:
            return f"the cached available controllers {gone} are no longer offered by {parent}"
    return None


def revalidate_cgroup_topology(topology: CgroupTopology) -> str | None:
    """Public form of the cached-topology revalidation (M2-B29)."""

    return _topology_is_still_true(topology)


def initialize_cgroup_topology(
    *,
    force: bool = False,
    unified_root: Path | str | None = None,
    own_cgroup: str | None = None,
    require_cgroup2: bool = True,
    cache: bool = True,
) -> CgroupTopology:
    """Bootstrap -- or truthfully reuse -- the trusted manager-leaf topology.

    The keyword arguments other than ``force`` exist so the deterministic fault
    tests can drive every transition against a constructed directory tree.  They
    never relax the evidence rule: with ``require_cgroup2`` left at its default
    an ordinary filesystem fixture is refused as
    ``DELEGATED_PATH_NOT_CGROUP2``, which is exactly what
    :func:`probe_cgroup_delegation` and every production caller use.
    """

    global _TOPOLOGY
    injected = unified_root is not None or own_cgroup is not None
    use_cache = cache and not injected
    with _TOPOLOGY_LOCK:
        if use_cache and _TOPOLOGY is not None and not force:
            cached = _TOPOLOGY
            if cached.initialized:
                stale = _topology_is_still_true(cached)
                if stale is None:
                    return cached
                # A manager path that has been removed, replaced, or inherited
                # by a different process is never silently re-bootstrapped.
                _TOPOLOGY = _failed(
                    TOPOLOGY_STALE_CACHED_TOPOLOGY,
                    stale,
                    unified_root=cached.unified_root,
                    effect_parent=cached.effect_parent,
                    manager_leaf=cached.manager_leaf,
                    owner_pid=cached.owner_pid,
                )
                return _TOPOLOGY
            return cached

        topology = _bootstrap_topology(
            unified_root=unified_root,
            own_cgroup=own_cgroup,
            require_cgroup2=require_cgroup2,
        )
        if use_cache:
            _TOPOLOGY = topology
        return topology


def _bootstrap_topology(
    *,
    unified_root: Path | str | None,
    own_cgroup: str | None,
    require_cgroup2: bool,
) -> CgroupTopology:
    root = Path(unified_root) if unified_root is not None else CGROUP_V2_ROOT
    own = own_cgroup if own_cgroup is not None else _own_unified_cgroup()
    pid = os.getpid()

    if own is None:
        return _failed(TOPOLOGY_NO_UNIFIED_CGROUP_V2, "this process has no cgroup v2 unified hierarchy")
    if not root.is_dir():
        return _failed(TOPOLOGY_CGROUP2_NOT_MOUNTED, f"{root} is not a directory")
    if require_cgroup2 and not is_cgroup2_filesystem(root):
        return _failed(
            TOPOLOGY_CGROUP2_NOT_MOUNTED,
            f"{root} is not a cgroup2 mount (f_type={statfs_f_type(root)})",
            unified_root=str(root),
        )

    own_directory = root / own.lstrip("/")
    if not own_directory.is_dir():
        return _failed(
            TOPOLOGY_DELEGATED_PATH_MISSING,
            f"{own_directory} does not exist",
            unified_root=str(root),
            unified_cgroup=own,
        )
    if require_cgroup2 and not is_cgroup2_filesystem(own_directory):
        return _failed(
            TOPOLOGY_DELEGATED_PATH_NOT_CGROUP2,
            f"{own_directory} is not on a cgroup2 filesystem",
            unified_root=str(root),
            unified_cgroup=own,
        )

    if own_directory.name.startswith(MANAGER_LEAF_PREFIX):
        # We are already inside a manager leaf.  Reuse it; never nest another
        # one and never reinterpret the leaf as a new delegated parent.
        return _reuse_manager_leaf(
            root=root,
            own=own,
            manager=own_directory,
            parent=own_directory.parent,
            pid=pid,
            require_cgroup2=require_cgroup2,
        )

    parent = own_directory
    raw_controllers, control_error = _read_control(parent / "cgroup.controllers")
    if raw_controllers is None:
        return _failed(
            TOPOLOGY_CONTROLLERS_UNREADABLE,
            f"cgroup.controllers is unreadable: {control_error}",
            unified_root=str(root),
            unified_cgroup=own,
            effect_parent=str(parent),
        )
    available = tuple(raw_controllers.split())
    missing = [name for name in REQUIRED_CONTROLLERS if name not in available]
    if missing:
        return _failed(
            TOPOLOGY_MISSING_CONTROLLERS,
            f"the delegated cgroup lacks {missing}",
            unified_root=str(root),
            unified_cgroup=own,
            effect_parent=str(parent),
            available_controllers=available,
        )

    common = {
        "unified_root": str(root),
        "unified_cgroup": own,
        "effect_parent": str(parent),
        "available_controllers": available,
        "owner_pid": pid,
    }

    manager = parent / f"{MANAGER_LEAF_PREFIX}-{pid}"
    try:
        manager.mkdir(mode=0o700)
    except FileExistsError:
        return _failed(
            TOPOLOGY_MANAGER_COLLISION,
            f"{manager} already exists; a second manager leaf is never created over it",
            manager_leaf=str(manager),
            **common,
        )
    except OSError as error:
        return _failed(
            TOPOLOGY_MANAGER_CREATE_FAILED,
            f"{manager}: {_errno_name(error)}",
            manager_leaf=str(manager),
            **common,
        )

    def _rollback(code: str, detail: str) -> CgroupTopology:
        # Restore the prior state where that is physically safe: move the
        # controller back to the parent and remove the leaf we created.  When
        # it is not safe the leaf is left in place and reported, never hidden.
        moved_back = _write_control(parent / "cgroup.procs", str(pid)) is None
        removed = False
        # M2-B35.  A cgroup is removed only when its emptiness was observed.
        # An unreadable membership leaves the leaf in place and says so.
        leaf_members = read_cgroup_members(manager)
        if leaf_members.observed_empty:
            try:
                manager.rmdir()
                removed = True
            except OSError:
                removed = False
        return _failed(
            code,
            (
                f"{detail}; rollback: controller_returned={moved_back} manager_leaf_removed={removed}"
                + ("" if leaf_members.usable else f" ({leaf_members.refusal_detail()})")
            ),
            manager_leaf=str(manager),
            **common,
        )

    move_error = _write_control(manager / "cgroup.procs", str(pid))
    if move_error is not None:
        return _rollback(TOPOLOGY_CONTROLLER_MOVE_FAILED, f"{manager}/cgroup.procs: {move_error}")

    manager_members = read_cgroup_members(manager)
    if not manager_members.usable:
        return _rollback(_membership_code(manager_members), manager_members.refusal_detail())
    if pid not in manager_members.pids:
        return _rollback(
            TOPOLOGY_CONTROLLER_MOVE_NOT_OBSERVED,
            f"{pid} is not a member of {manager} after the move",
        )
    if require_cgroup2:
        observed = _own_unified_cgroup()
        if observed is None or Path(observed).name != manager.name:
            return _rollback(
                TOPOLOGY_CONTROLLER_MOVE_NOT_OBSERVED,
                f"/proc/self/cgroup reports {observed}, not {manager.name}",
            )

    parent_members = read_cgroup_members(parent)
    if not parent_members.usable:
        # M2-B35.  Positive readiness requires the parent to have been *observed*
        # unpopulated.  A failed read is refused rather than counted as empty.
        return _rollback(_membership_code(parent_members), parent_members.refusal_detail())
    if parent_members.opaque_member_count:
        return _rollback(
            TOPOLOGY_PARENT_STILL_POPULATED,
            f"the delegated parent holds {parent_members.opaque_member_count} member(s) this PID "
            "namespace cannot name, so its depopulation cannot be observed",
        )
    remaining = set(parent_members.pids) - {pid}
    if remaining:
        # Unrelated processes are never moved.  Refusing here keeps the
        # no-internal-process constraint an observation rather than an action
        # taken on somebody else's process.
        return _rollback(
            TOPOLOGY_PARENT_STILL_POPULATED,
            f"the delegated parent still holds {sorted(remaining)}",
        )

    write_error = _write_control(
        parent / "cgroup.subtree_control",
        " ".join(f"+{name}" for name in REQUIRED_CONTROLLERS) + "\n",
    )
    if write_error is not None:
        return _rollback(
            TOPOLOGY_SUBTREE_CONTROL_WRITE_FAILED,
            f"{parent}/cgroup.subtree_control: {write_error}",
        )

    enabled, enabled_error = _enabled_controllers(parent)
    if enabled is None:
        return _rollback(
            TOPOLOGY_SUBTREE_CONTROL_UNREADABLE,
            f"{parent}/cgroup.subtree_control: {enabled_error}",
        )
    absent = [name for name in REQUIRED_CONTROLLERS if name not in enabled]
    if absent:
        return _rollback(
            TOPOLOGY_CONTROLLER_READBACK_MISMATCH,
            f"cgroup.subtree_control reads {list(enabled)}; {absent} did not activate",
        )

    return CgroupTopology(
        initialized=True,
        code=TOPOLOGY_INITIALIZED,
        detail=(
            f"the controller runs in the trusted manager leaf {manager.name} and the delegated "
            f"parent distributes {list(enabled)} to sibling effect cgroups"
        ),
        manager_leaf=str(manager),
        enabled_controllers=tuple(enabled),
        manager_leaf_created=True,
        effect_parent_identity=_directory_identity(parent),
        manager_leaf_identity=_directory_identity(manager),
        owner_unified_path=_unified_path_of(root, manager),
        cgroup2_required=require_cgroup2,
        **common,
    )


def _reuse_manager_leaf(
    *, root: Path, own: str, manager: Path, parent: Path, pid: int, require_cgroup2: bool = True
) -> CgroupTopology:
    """Reuse an existing manager leaf this process is already a member of."""

    raw_controllers, control_error = _read_control(parent / "cgroup.controllers")
    if raw_controllers is None:
        return _failed(
            TOPOLOGY_CONTROLLERS_UNREADABLE,
            f"{parent}/cgroup.controllers: {control_error}",
            unified_root=str(root),
            unified_cgroup=own,
            effect_parent=str(parent),
            manager_leaf=str(manager),
        )
    available = tuple(raw_controllers.split())
    common = {
        "unified_root": str(root),
        "unified_cgroup": own,
        "effect_parent": str(parent),
        "manager_leaf": str(manager),
        "available_controllers": available,
        "owner_pid": pid,
    }
    parent_members = read_cgroup_members(parent)
    if not parent_members.usable:
        return _failed(_membership_code(parent_members), parent_members.refusal_detail(), **common)
    if parent_members.observed_populated:
        return _failed(
            TOPOLOGY_PARENT_STILL_POPULATED,
            f"the effect parent {parent} holds {list(parent_members.pids)}"
            + (
                f" plus {parent_members.opaque_member_count} unnameable member(s)"
                if parent_members.opaque_member_count
                else ""
            ),
            **common,
        )
    enabled, enabled_error = _enabled_controllers(parent)
    if enabled is None:
        return _failed(
            TOPOLOGY_SUBTREE_CONTROL_UNREADABLE,
            f"{parent}/cgroup.subtree_control: {enabled_error}",
            **common,
        )
    absent = [name for name in REQUIRED_CONTROLLERS if name not in enabled]
    if absent:
        return _failed(
            TOPOLOGY_CONTROLLER_READBACK_MISMATCH,
            f"cgroup.subtree_control reads {list(enabled)}; {absent} are not enabled",
            **common,
        )
    return CgroupTopology(
        initialized=True,
        code=TOPOLOGY_INITIALIZED,
        detail=f"the existing trusted manager leaf {manager.name} was reused; no leaf was nested",
        enabled_controllers=tuple(enabled),
        manager_leaf_created=False,
        effect_parent_identity=_directory_identity(parent),
        manager_leaf_identity=_directory_identity(manager),
        owner_unified_path=_unified_path_of(root, manager),
        cgroup2_required=require_cgroup2,
        **common,
    )


def topology_lifecycle_description() -> dict[str, Any]:
    """The explicit lifecycle of everything this module creates.

    The manager leaf is *not* claimed to be manually removed: it holds the live
    controller for as long as the controller runs, and a cgroup with members
    cannot be removed.  It is reclaimed when the containing delegated service or
    transient unit is torn down, which is stated rather than implied.
    """

    return {
        "manager_leaf": {
            "created": "once per controller process, on first topology initialization",
            "holds": "the trusted paired-runner controller process and its trusted helpers",
            "removed_by_this_process": False,
            "reclaimed_by": "teardown of the containing delegated service or transient systemd unit",
            "leak_claim": (
                "this is a disclosed residual cgroup, not a leak-free manual removal; a leaf "
                "containing the live controller is never reported as removed"
            ),
        },
        "effect_cgroup": {
            "created": "one sibling per effect, under the delegated effect parent",
            "removed": "after the effect process tree is quiescent",
            "removal_refused_when": "cgroup.procs still lists live members",
        },
        "interrupted_setup": "owned, empty cgroups are removed and the prior state restored where safe",
        "failed_launch": "the effect cgroup is removed once the killed child has been reaped",
        "unowned_cgroups": "never created, mutated, or removed",
    }


@dataclass(frozen=True)
class CgroupDelegation:
    """Whether this host actually hands us a cgroup subtree we may write.

    ``available`` is now a statement about a completed physical rehearsal: the
    manager-leaf topology was bootstrapped or reused, the delegated parent
    distributes ``memory`` and ``pids``, and a real probe effect carried finite
    ``pids.max`` and ``memory.max`` values that were read back from the kernel
    and compared exactly.
    """

    available: bool
    detail: str
    unified_root: str | None
    delegated_path: str | None
    controllers: tuple[str, ...]
    code: str = TOPOLOGY_NOT_INITIALIZED
    manager_leaf: str | None = None
    enabled_controllers: tuple[str, ...] = ()
    probe_effect_limits: dict[str, int] = field(default_factory=dict)
    #: M2-B28.  The completed, observed disposition of the probe cgroup.  A
    #: positive result is constructed only after this records a verified
    #: removal, so ``available`` can never coexist with a residual probe path.
    probe_cleanup: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "detail": self.detail,
            "unified_root": self.unified_root,
            "delegated_path": self.delegated_path,
            "controllers": list(self.controllers),
            "code": self.code,
            "manager_leaf": self.manager_leaf,
            "enabled_controllers": list(self.enabled_controllers),
            "probe_effect_limits": dict(self.probe_effect_limits),
            "probe_cleanup": dict(self.probe_cleanup),
        }


def _delegation_from_failure(
    topology: CgroupTopology, *, probe_cleanup: dict[str, Any] | None = None
) -> CgroupDelegation:
    return CgroupDelegation(
        available=False,
        detail=f"{topology.code}: {topology.detail}",
        unified_root=topology.unified_root,
        delegated_path=topology.effect_parent,
        controllers=topology.available_controllers,
        code=topology.code,
        manager_leaf=topology.manager_leaf,
        enabled_controllers=topology.enabled_controllers,
        probe_cleanup=dict(probe_cleanup or {}),
    )


def delegation_from_topology_failure(
    topology: CgroupTopology, *, probe_cleanup: dict[str, Any] | None = None
) -> CgroupDelegation:
    """Public form used by the supervisor when a cached topology goes stale."""

    return _delegation_from_failure(topology, probe_cleanup=probe_cleanup)


def _remove_owned_probe(probe: Path) -> dict[str, Any]:
    """Remove the probe cgroup this process created and prove it is gone.

    M2-B28.  The word "removed" is only ever produced by this function, and only
    when ``rmdir`` succeeded *and* the path was then observed to be absent.
    Every other outcome -- ``EBUSY``, ``EACCES``, a success that left the path
    behind, a disappearance this process did not perform -- is reported with its
    exact classification and with whether a residual path exists.
    """

    membership = read_cgroup_members(probe)
    evidence: dict[str, Any] = {
        "probe_path": str(probe),
        "owned": True,
        "members_before_removal": list(membership.pids),
        "membership_read": membership.to_dict(),
        "rmdir_attempted": False,
        "rmdir_errno": None,
        "removed": False,
        "absence_verified": False,
        "residual_path_exists": None,
        "code": None,
        "detail": "",
    }

    if not membership.usable:
        # M2-B35.  A cgroup is never removed on the strength of a membership
        # read that failed: it may hold live processes this controller cannot
        # see, and removing it would be an unproven claim about the domain.
        evidence["residual_path_exists"] = probe.exists()
        evidence["code"] = TOPOLOGY_PROBE_MEMBERSHIP_UNREADABLE
        evidence["detail"] = (
            f"{membership.refusal_detail()}; an unreadable probe cgroup is never removed and "
            "never reported removed"
        )
        return evidence

    if membership.observed_populated:
        evidence["residual_path_exists"] = probe.exists()
        evidence["code"] = TOPOLOGY_PROBE_NOT_EMPTY
        evidence["detail"] = (
            f"{probe} still holds {evidence['members_before_removal']}"
            + (
                f" plus {membership.opaque_member_count} unnameable member(s)"
                if membership.opaque_member_count
                else ""
            )
            + "; an occupied probe cgroup is never removed and never reported removed"
        )
        return evidence

    evidence["rmdir_attempted"] = True
    try:
        probe.rmdir()
    except FileNotFoundError as error:
        # This process created the probe and has not removed it.  Something else
        # did.  Disappearance is not proof of a safe, expected removal, so it is
        # classified rather than treated as success.
        evidence["rmdir_errno"] = _errno_name(error)
        evidence["residual_path_exists"] = probe.exists()
        evidence["code"] = TOPOLOGY_PROBE_DISAPPEARED
        evidence["detail"] = (
            f"{probe} was already gone when this process removed it (ENOENT); the owned probe "
            "cgroup's lifecycle was not under this controller's sole control"
        )
        return evidence
    except OSError as error:
        evidence["rmdir_errno"] = _errno_name(error)
        evidence["residual_path_exists"] = probe.exists()
        evidence["code"] = TOPOLOGY_PROBE_CLEANUP_FAILED
        evidence["detail"] = f"{probe}: rmdir failed with {evidence['rmdir_errno']}"
        return evidence

    # rmdir returned success.  That is a claim, not an observation; check.
    still_there = probe.exists()
    evidence["residual_path_exists"] = still_there
    if still_there:
        evidence["code"] = TOPOLOGY_PROBE_RESIDUAL_PATH
        evidence["detail"] = (
            f"rmdir reported success but {probe} still exists; no availability is claimed over a "
            "residual probe cgroup"
        )
        return evidence
    evidence["removed"] = True
    evidence["absence_verified"] = True
    evidence["detail"] = f"{probe} was removed and its absence was verified"
    return evidence


def probe_cgroup_delegation(*, force: bool = False) -> CgroupDelegation:
    """Physically rehearse everything a per-effect cgroup will later need.

    Creating and removing an empty directory proves nothing: cgroup v2 refuses
    to distribute controllers out of a cgroup that still holds processes, so the
    directory can exist while every limit write into it fails with ``EACCES``.
    This probe therefore bootstraps the trusted manager-leaf topology, then
    creates a real probe effect, writes ``pids.max`` and ``memory.max``, reads
    both back, compares them exactly, and removes the probe effect.
    """

    topology = initialize_cgroup_topology(force=force)
    if not topology.initialized or topology.effect_parent is None:
        return _delegation_from_failure(topology)

    parent = Path(topology.effect_parent)
    bounds = ResourceBounds.for_timeout(0)
    intended = {
        "pids.max": bounds.max_processes,
        "memory.max": bounds.max_address_space_bytes,
    }
    probe = parent / f"{PROBE_PREFIX}{os.getpid()}"
    try:
        probe.mkdir(mode=0o700)
    except FileExistsError:
        return _delegation_from_failure(
            _failed(
                TOPOLOGY_EFFECT_COLLISION,
                f"{probe} already exists",
                unified_root=topology.unified_root,
                effect_parent=str(parent),
                manager_leaf=topology.manager_leaf,
                available_controllers=topology.available_controllers,
                enabled_controllers=topology.enabled_controllers,
            )
        )
    except OSError as error:
        return _delegation_from_failure(
            _failed(
                TOPOLOGY_EFFECT_CREATE_FAILED,
                f"{probe}: {_errno_name(error)}",
                unified_root=topology.unified_root,
                effect_parent=str(parent),
                manager_leaf=topology.manager_leaf,
                available_controllers=topology.available_controllers,
                enabled_controllers=topology.enabled_controllers,
            )
        )
    def _refuse(code: str, detail: str, cleanup: dict[str, Any] | None = None) -> CgroupDelegation:
        return _delegation_from_failure(
            _failed(
                code,
                detail,
                unified_root=topology.unified_root,
                effect_parent=str(parent),
                manager_leaf=topology.manager_leaf,
                available_controllers=topology.available_controllers,
                enabled_controllers=topology.enabled_controllers,
            ),
            probe_cleanup=cleanup,
        )

    # M2-B28.  Nothing below constructs a positive result.  The limits are
    # rehearsed, the probe is removed, and its absence is verified *first*; only
    # then is availability stated, and the statement is built from the cleanup
    # evidence rather than asserted alongside it.
    code, detail, observed = _apply_and_read_back_limits(probe, intended)
    cleanup = _remove_owned_probe(probe)
    if code is not None:
        return _refuse(code, f"{detail}; probe cleanup: {cleanup['detail'] or 'removed'}", cleanup)
    if cleanup["code"] is not None:
        # The rehearsal itself succeeded, but this controller cannot prove it
        # left the delegated parent as it found it.  Refuse: a residual probe
        # cgroup would collide with the next probe and is never called removed.
        return _refuse(cleanup["code"], cleanup["detail"], cleanup)
    if not cleanup["removed"] or not cleanup["absence_verified"]:  # pragma: no cover - defensive
        return _refuse(
            TOPOLOGY_PROBE_CLEANUP_FAILED,
            f"probe cleanup did not prove removal: {cleanup}",
            cleanup,
        )
    return CgroupDelegation(
        available=True,
        detail=(
            "a real effect cgroup was created beneath the delegated parent, carried finite "
            f"{sorted(observed)} read back from the kernel, and was removed with its absence "
            "verified"
        ),
        unified_root=topology.unified_root,
        delegated_path=topology.effect_parent,
        controllers=topology.available_controllers,
        code=TOPOLOGY_INITIALIZED,
        manager_leaf=topology.manager_leaf,
        enabled_controllers=topology.enabled_controllers,
        probe_effect_limits=observed,
        probe_cleanup=cleanup,
    )


def _apply_and_read_back_limits(
    cgroup: Path, intended: dict[str, int]
) -> tuple[str | None, str, dict[str, int]]:
    """Write every intended limit and prove the kernel holds exactly it."""

    for name, value in sorted(intended.items()):
        error = _write_control(cgroup / name, f"{value}\n")
        if error is not None:
            return TOPOLOGY_LIMIT_WRITE_FAILED, f"{cgroup / name}: {error}", {}
    observed: dict[str, int] = {}
    for name, value in sorted(intended.items()):
        raw, read_error = _read_control(cgroup / name)
        if raw is None:
            return TOPOLOGY_LIMIT_READBACK_MISMATCH, f"{cgroup / name} is unreadable: {read_error}", {}
        parsed = _parse_limit(raw)
        if parsed is None:
            return (
                TOPOLOGY_LIMIT_READBACK_MISMATCH,
                f"{cgroup / name} reads {raw.strip()!r}, which is not the finite bound {value}",
                {},
            )
        if parsed != value:
            return (
                TOPOLOGY_LIMIT_READBACK_MISMATCH,
                f"{cgroup / name} reads {parsed}, not the intended {value}",
                {},
            )
        observed[name] = parsed
    return None, "", observed


class EffectCgroup:
    """One per-effect cgroup v2 subtree, or an inert object when undelegated.

    The subtree is created as a *sibling* of the trusted manager leaf, directly
    beneath the delegated effect parent, so it inherits the ``memory`` and
    ``pids`` controllers the parent distributes.  ``active`` means the subtree
    exists, both limits were read back from the kernel exactly as intended,
    *and* at least one verified member has been attached.  Directory creation
    alone is never membership and never containment.
    """

    def __init__(self, delegation: CgroupDelegation, bounds: ResourceBounds, label: str) -> None:
        self._delegation = delegation
        self._bounds = bounds
        self._path: Path | None = None
        self._label = label
        self._membership_verified = False
        self.applied: dict[str, Any] = {}
        self.intended: dict[str, int] = {
            "pids.max": bounds.max_processes,
            "memory.max": bounds.max_address_space_bytes,
        }
        self.create_error: str | None = None
        self.attach_error: str | None = None
        self._removal_evidence: dict[str, Any] = {}

    @property
    def active(self) -> bool:
        return self._path is not None and self._membership_verified

    @property
    def directory_present(self) -> bool:
        return self._path is not None

    @property
    def path(self) -> str | None:
        return None if self._path is None else str(self._path)

    def create(self) -> bool:
        """Create the subtree and prove its limits.  ``False`` means refuse.

        Returns ``True`` unchanged when this host delegates nothing, because
        there is then no cgroup layer to fail; the ``RLIMIT`` layer still
        applies and readiness already recorded that honestly.
        """

        if not self._delegation.available or self._delegation.delegated_path is None:
            return True
        if not _SAFE_LABEL.match(self._label):
            self.create_error = TOPOLOGY_INVALID_LABEL
            return False
        candidate = Path(self._delegation.delegated_path) / f"{EFFECT_PREFIX}{self._label}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            # Never adopt a cgroup this process did not create.
            self.create_error = TOPOLOGY_EFFECT_COLLISION
            return False
        except OSError as error:
            self.create_error = _errno_name(error)
            return False
        code, detail, observed = _apply_and_read_back_limits(candidate, self.intended)
        if code is not None:
            self.create_error = f"{code}:{detail}"
            # The cgroup is ours and has no members; removing it leaves no
            # partial state behind.
            self._remove(candidate)
            return False
        self._path = candidate
        self.applied = dict(observed)
        return True

    def read_members(self) -> CgroupMembership:
        """The typed membership observation for this effect cgroup (M2-B35)."""

        if self._path is None:
            return CgroupMembership("", read_ok=True, pids=())
        return read_cgroup_members(self._path)

    def members(self) -> set[int]:
        """The observed member PIDs.

        This raises rather than returning an empty set when the read failed: an
        empty set is an answer, and a failed read is not.
        """

        membership = self.read_members()
        if not membership.usable:
            raise CgroupMembershipUnreadable(membership)
        return set(membership.pids)

    def attach(self, pid: int) -> bool:
        if self._path is None:
            return False
        error = _write_control(self._path / "cgroup.procs", str(pid))
        if error is not None:
            self.attach_error = error
            return False
        return True

    def attach_and_verify(self, pid: int) -> bool:
        """Move ``pid`` into the cgroup and prove kernel membership before release.

        Three separate observations, each of which must succeed on its own
        terms: this cgroup was observed empty before the attach (it was created
        by this controller moments ago and adopting an occupied cgroup is never
        permitted), the write succeeded, and the kernel then listed exactly this
        PID.  A membership read that fails at either end refuses; it is never
        read as "empty" and never as "verified".
        """

        if self._path is None:
            return False
        before = self.read_members()
        if not before.usable:
            self.attach_error = f"pre_attach_membership_unreadable:{before.error_code or before.malformed_detail}"
            return False
        if before.observed_populated:
            self.attach_error = (
                f"effect_cgroup_not_empty_before_attach:{list(before.pids)}"
                f"+{before.opaque_member_count}_unnameable"
            )
            return False
        if not self.attach(pid):
            return False
        after = self.read_members()
        if not after.usable:
            self.attach_error = f"post_attach_membership_unreadable:{after.error_code or after.malformed_detail}"
            return False
        if pid not in after.pids:
            self.attach_error = "membership_not_observed"
            return False
        self._membership_verified = True
        return True

    def observed_membership(self, pid: int) -> dict[str, Any]:
        """Corroborating evidence for one member, from two independent files."""

        membership = self.read_members()
        return {
            "effect_path": self.path,
            "cgroup_procs_members": list(membership.pids),
            "cgroup_procs_read": membership.to_dict(),
            "proc_pid_cgroup": _pid_unified_cgroup(pid),
            "membership_verified": self._membership_verified,
        }

    def kill_domain(self) -> dict[str, Any]:
        """Terminate every process accounted to this cgroup, and nothing else.

        ``cgroup.kill`` is used when the kernel offers it, because it is atomic
        over the whole subtree and cannot race a fork.  Where it is absent the
        observed members are signalled individually, which is bounded by the
        membership list this cgroup owns: no unrelated process is ever reached,
        because a PID that is not in *this* cgroup is never signalled.
        """

        evidence: dict[str, Any] = {
            "effect_path": self.path,
            "mechanism": None,
            "members_signalled": [],
            "membership_readable": True,
            "errors": [],
        }
        if self._path is None:
            evidence["mechanism"] = "NO_CGROUP"
            return evidence
        membership = self.read_members()
        evidence["membership_readable"] = membership.usable
        if not membership.usable:
            evidence["errors"].append(f"cgroup.procs:{membership.refusal_detail()}")
        kill_file = self._path / "cgroup.kill"
        if kill_file.exists():
            error = _write_control(kill_file, "1\n")
            evidence["mechanism"] = "CGROUP_KILL"
            # cgroup.kill is atomic over the whole subtree and does not depend on
            # this controller enumerating anything, so it is still the right
            # action when the membership read failed -- but the member list that
            # goes into the evidence is only ever what was actually observed.
            evidence["members_signalled"] = list(membership.pids) if membership.usable else []
            if error is not None:
                evidence["errors"].append(f"cgroup.kill:{error}")
            else:
                return evidence
        evidence["mechanism"] = "SIGKILL_MEMBERS" if evidence["mechanism"] is None else evidence["mechanism"]
        if not membership.fully_addressable:
            # M2-B35.  Without a complete, observed member list there is nothing
            # this controller may signal individually: a guessed PID is somebody
            # else's process, and a member this PID namespace cannot name has no
            # number to signal at all.
            evidence["members_signalled"] = []
            if membership.usable and membership.opaque_member_count:
                evidence["errors"].append(
                    f"unnameable_members:{membership.opaque_member_count}"
                )
            return evidence
        for pid in membership.pids:
            try:
                os.kill(pid, 9)
            except OSError as error:
                evidence["errors"].append(f"{pid}:{_errno_name(error)}")
        evidence["members_signalled"] = list(membership.pids)
        return evidence

    def wait_quiescent(self, timeout_seconds: float) -> dict[str, Any]:
        """Wait, boundedly, for the cgroup to hold no members.

        Quiescence is a positive observation of an empty ``cgroup.procs``.  A
        read that failed is reported as not-quiescent with its exact refusal,
        never as the empty list that would have satisfied the caller.
        """

        evidence: dict[str, Any] = {
            "effect_path": self.path,
            "quiescent": True,
            "residual_members": [],
            "membership_readable": True,
            "detail": "",
        }
        if self._path is None:
            return evidence
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            membership = self.read_members()
            if membership.observed_empty:
                evidence["quiescent"] = True
                evidence["residual_members"] = []
                evidence["membership_readable"] = True
                return evidence
            if time.monotonic() >= deadline:
                evidence["quiescent"] = False
                evidence["membership_readable"] = membership.usable
                evidence["residual_members"] = list(membership.pids)
                evidence["opaque_member_count"] = membership.opaque_member_count
                evidence["detail"] = membership.refusal_detail()
                return evidence
            time.sleep(0.01)

    def removal_evidence(self) -> dict[str, Any]:
        """The truthful disposition of this cgroup after :meth:`close`."""

        return dict(self._removal_evidence)

    def close(self) -> bool:
        """Remove the subtree.  Returns False if live members prevent removal.

        Idempotent: after a successful removal the object holds no path, and a
        repeated call is a no-op that neither touches the filesystem nor reports
        a second success as though it had removed something again.
        """

        if self._path is None:
            # Idempotent: either nothing was ever created, or a previous call
            # removed it.  Neither is a second removal, and neither is reported
            # as one.
            self._removal_evidence = {
                "effect_path": self._removal_evidence.get("effect_path"),
                "removed": False,
                "absence_verified": True,
                "residual_path_exists": False,
                "detail": (
                    "the per-effect cgroup is already absent; this call removed nothing"
                    if self._removal_evidence
                    else "no per-effect cgroup was ever created"
                ),
            }
            return True
        path = self._path
        membership = self.read_members()
        if not membership.usable:
            # M2-B35.  Removal eligibility is emptiness, and emptiness was not
            # observed.  The cgroup stays, and the refusal says exactly why.
            self.attach_error = f"membership_unreadable:{membership.error_code or membership.malformed_detail}"
            self._removal_evidence = {
                "effect_path": str(path),
                "removed": False,
                "absence_verified": False,
                "residual_path_exists": path.exists(),
                "residual_members": [],
                "membership_readable": False,
                "code": _membership_code(membership),
                "detail": (
                    f"{membership.refusal_detail()}; a cgroup whose membership cannot be read is "
                    "never removed and never reported removed"
                ),
            }
            return False
        if membership.observed_populated:
            live = membership.pids
            self.attach_error = (
                f"live_members:{list(live)}"
                + (f"+{membership.opaque_member_count}_unnameable" if membership.opaque_member_count else "")
            )
            self._removal_evidence = {
                "effect_path": str(path),
                "removed": False,
                "absence_verified": False,
                "residual_path_exists": True,
                "residual_members": list(live),
                "membership_readable": True,
                "detail": f"{path} still holds {list(live)}; it is not removed and not called removed",
            }
            return False
        removed, rmdir_error = self._remove(path)
        residual = path.exists()
        self._removal_evidence = {
            "effect_path": str(path),
            "removed": bool(removed and not residual),
            "absence_verified": not residual,
            "residual_path_exists": residual,
            "membership_readable": True,
            "rmdir_errno": rmdir_error,
            "detail": (
                f"{path} was removed and its absence was verified"
                if removed and not residual
                else f"{path}: rmdir removed={removed} errno={rmdir_error} residual_path={residual}"
            ),
        }
        if removed and not residual:
            self._path = None
            self._membership_verified = False
            return True
        return False

    @staticmethod
    def _remove(path: Path) -> tuple[bool, str | None]:
        try:
            path.rmdir()
            return True, None
        except OSError as error:
            return False, _errno_name(error)


# --- the mechanism actually in force ----------------------------------------

def effective_mechanism(
    delegation: CgroupDelegation,
    *,
    membership_verified: bool,
    required_mechanism: str | None = None,
) -> str:
    """Return the mechanism that was physically proven for this effect.

    Directory existence is not membership.  When readiness promised
    ``CGROUP_V2_AND_RLIMIT``, callers must refuse rather than silently report
    ``RLIMIT`` after an attach failure.
    """

    if delegation.available and membership_verified:
        return MECHANISM_CGROUP_AND_RLIMIT
    if required_mechanism == MECHANISM_CGROUP_AND_RLIMIT and not membership_verified:
        return MECHANISM_NONE
    return MECHANISM_RLIMIT


def containment_semantics(mechanism: str) -> str:
    if mechanism == MECHANISM_CGROUP_AND_RLIMIT:
        return (
            "A per-effect cgroup v2 subtree bounded the whole process domain in aggregate "
            "(pids.max, memory.max) and setrlimit bounded each process inside the capsule "
            "(processes, address space, CPU seconds, open files, file size, core dumps)."
        )
    if mechanism == MECHANISM_RLIMIT:
        return (
            "This host delegates no writable cgroup v2 subtree, so aggregate accounting is "
            "unavailable and containment is the setrlimit layer applied inside the capsule "
            "immediately before execv: processes, address space, CPU seconds, open files, file "
            "size, and a prohibited core dump.  Readiness physically proved each bound before "
            "any effect was permitted."
        )
    return "No resource containment was enforced; no effect may be attempted under this mechanism."


__all__ = [
    "CGROUP2_SUPER_MAGIC",
    "CGROUP_V2_ROOT",
    "CONTAINMENT_MECHANISMS",
    "CORE_DUMP_BYTES",
    "CPU_SECONDS_HEADROOM",
    "CgroupDelegation",
    "CgroupMembership",
    "CgroupMembershipUnreadable",
    "CgroupTopology",
    "EFFECT_PREFIX",
    "MANAGER_LEAF_PREFIX",
    "PROBE_PREFIX",
    "REQUIRED_CONTROLLERS",
    "TOPOLOGY_CODES",
    "TOPOLOGY_CONTROLLER_MOVE_FAILED",
    "TOPOLOGY_CONTROLLER_MOVE_NOT_OBSERVED",
    "TOPOLOGY_CONTROLLER_READBACK_MISMATCH",
    "TOPOLOGY_CONTROLLERS_UNREADABLE",
    "TOPOLOGY_CGROUP2_NOT_MOUNTED",
    "TOPOLOGY_DELEGATED_PATH_MISSING",
    "TOPOLOGY_DELEGATED_PATH_NOT_CGROUP2",
    "TOPOLOGY_EFFECT_COLLISION",
    "TOPOLOGY_EFFECT_CREATE_FAILED",
    "TOPOLOGY_INITIALIZED",
    "TOPOLOGY_INVALID_LABEL",
    "TOPOLOGY_LIMIT_READBACK_MISMATCH",
    "TOPOLOGY_LIMIT_WRITE_FAILED",
    "TOPOLOGY_MANAGER_COLLISION",
    "TOPOLOGY_MANAGER_CREATE_FAILED",
    "TOPOLOGY_MEMBERSHIP_MALFORMED",
    "TOPOLOGY_MEMBERSHIP_UNREADABLE",
    "TOPOLOGY_MISSING_CONTROLLERS",
    "TOPOLOGY_NO_UNIFIED_CGROUP_V2",
    "TOPOLOGY_NOT_INITIALIZED",
    "TOPOLOGY_PARENT_STILL_POPULATED",
    "TOPOLOGY_PROBE_CLEANUP_FAILED",
    "TOPOLOGY_PROBE_DISAPPEARED",
    "TOPOLOGY_PROBE_MEMBERSHIP_UNREADABLE",
    "TOPOLOGY_PROBE_NOT_EMPTY",
    "TOPOLOGY_PROBE_RESIDUAL_PATH",
    "TOPOLOGY_STALE_CACHED_TOPOLOGY",
    "TOPOLOGY_SUBTREE_CONTROL_UNREADABLE",
    "TOPOLOGY_SUBTREE_CONTROL_WRITE_FAILED",
    "initialize_cgroup_topology",
    "is_cgroup2_filesystem",
    "statfs_f_type",
    "topology_lifecycle_description",
    "DEFAULT_MAX_ADDRESS_SPACE_BYTES",
    "DEFAULT_MAX_FILE_SIZE_BYTES",
    "DEFAULT_MAX_OPEN_FILES",
    "DEFAULT_MAX_PROCESSES",
    "EffectCgroup",
    "MECHANISM_CGROUP_AND_RLIMIT",
    "MECHANISM_NONE",
    "MECHANISM_RLIMIT",
    "ResourceBounds",
    "ResourceContainmentUnavailable",
    "containment_semantics",
    "delegation_from_topology_failure",
    "effective_mechanism",
    "probe_cgroup_delegation",
    "read_cgroup_members",
    "revalidate_cgroup_topology",
]
