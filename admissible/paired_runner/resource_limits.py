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
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import math
import os
from pathlib import Path
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
    """The required bounds cannot be enforced, so no effect may be attempted."""


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

@dataclass(frozen=True)
class CgroupDelegation:
    """Whether this host actually hands us a cgroup subtree we may write."""

    available: bool
    detail: str
    unified_root: str | None
    delegated_path: str | None
    controllers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "detail": self.detail,
            "unified_root": self.unified_root,
            "delegated_path": self.delegated_path,
            "controllers": list(self.controllers),
        }


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


def probe_cgroup_delegation() -> CgroupDelegation:
    """Physically test whether a per-effect cgroup can be created and removed.

    Presence of ``/sys/fs/cgroup`` proves nothing: an unprivileged process on a
    host without delegation cannot create a subtree there.  This probe therefore
    creates a real directory, requires the controllers it needs, and removes it.
    """

    own = _own_unified_cgroup()
    if own is None:
        return CgroupDelegation(False, "no cgroup v2 unified hierarchy for this process", None, None, ())
    if not CGROUP_V2_ROOT.is_dir():
        return CgroupDelegation(False, "the cgroup v2 hierarchy is not mounted", None, None, ())

    parent = CGROUP_V2_ROOT / own.lstrip("/")
    if not parent.is_dir():
        return CgroupDelegation(
            False, f"the delegated cgroup path {parent} does not exist", str(CGROUP_V2_ROOT), None, ()
        )
    try:
        controllers = tuple(
            (parent / "cgroup.controllers").read_text(encoding="utf-8").split()
        )
    except OSError as error:
        return CgroupDelegation(
            False,
            f"cgroup.controllers is unreadable: {errno.errorcode.get(error.errno, error.errno)}",
            str(CGROUP_V2_ROOT),
            str(parent),
            (),
        )
    required = {"pids", "memory"}
    if not required.issubset(set(controllers)):
        return CgroupDelegation(
            False,
            f"the delegated cgroup lacks the required controllers {sorted(required - set(controllers))}",
            str(CGROUP_V2_ROOT),
            str(parent),
            controllers,
        )

    probe = parent / f".admissible-cgroup-probe-{os.getpid()}"
    try:
        probe.mkdir(mode=0o700)
    except OSError as error:
        return CgroupDelegation(
            False,
            f"no cgroup subtree may be created here: {errno.errorcode.get(error.errno, error.errno)}",
            str(CGROUP_V2_ROOT),
            str(parent),
            controllers,
        )
    try:
        return CgroupDelegation(True, "a per-effect cgroup was created and removed", str(CGROUP_V2_ROOT), str(parent), controllers)
    finally:
        try:
            probe.rmdir()
        except OSError:  # pragma: no cover - the probe directory is ours
            pass


class EffectCgroup:
    """One per-effect cgroup v2 subtree, or an inert object when undelegated.

    ``active`` means the subtree exists *and* at least one verified member has
    been attached.  Directory creation alone is not membership.
    """

    def __init__(self, delegation: CgroupDelegation, bounds: ResourceBounds, label: str) -> None:
        self._delegation = delegation
        self._bounds = bounds
        self._path: Path | None = None
        self._label = label
        self._membership_verified = False
        self.applied: dict[str, Any] = {}
        self.create_error: str | None = None
        self.attach_error: str | None = None

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
        """Create the subtree.  Returns False when delegation promised one but creation failed."""

        if not self._delegation.available or self._delegation.delegated_path is None:
            return True
        candidate = Path(self._delegation.delegated_path) / f".admissible-effect-{self._label}"
        try:
            candidate.mkdir(mode=0o700)
            (candidate / "pids.max").write_text(str(self._bounds.max_processes), encoding="utf-8")
            (candidate / "memory.max").write_text(str(self._bounds.max_address_space_bytes), encoding="utf-8")
        except OSError as error:
            self.create_error = errno.errorcode.get(error.errno, str(error.errno))
            self._remove(candidate)
            return False
        self._path = candidate
        self.applied = {
            "pids.max": self._bounds.max_processes,
            "memory.max": self._bounds.max_address_space_bytes,
        }
        return True

    def members(self) -> set[int]:
        if self._path is None:
            return set()
        try:
            raw = (self._path / "cgroup.procs").read_text(encoding="utf-8")
        except OSError:
            return set()
        return {int(token) for token in raw.split() if token.isdigit()}

    def attach(self, pid: int) -> bool:
        if self._path is None:
            return False
        try:
            (self._path / "cgroup.procs").write_text(str(pid), encoding="utf-8")
        except OSError as error:
            self.attach_error = errno.errorcode.get(error.errno, str(error.errno))
            return False
        return True

    def attach_and_verify(self, pid: int) -> bool:
        """Move ``pid`` into the cgroup and prove kernel membership before release."""

        if self._path is None:
            return False
        if not self.attach(pid):
            return False
        if pid not in self.members():
            self.attach_error = "membership_not_observed"
            return False
        self._membership_verified = True
        return True

    def close(self) -> bool:
        """Remove the subtree.  Returns False if live members prevent removal."""

        if self._path is None:
            return True
        live = self.members()
        if live:
            self.attach_error = f"live_members:{sorted(live)}"
            return False
        removed = self._remove(self._path)
        if removed:
            self._path = None
            self._membership_verified = False
        return removed

    @staticmethod
    def _remove(path: Path) -> bool:
        try:
            path.rmdir()
            return True
        except OSError:
            return False


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
    "CGROUP_V2_ROOT",
    "CONTAINMENT_MECHANISMS",
    "CORE_DUMP_BYTES",
    "CPU_SECONDS_HEADROOM",
    "CgroupDelegation",
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
    "effective_mechanism",
    "probe_cgroup_delegation",
]
