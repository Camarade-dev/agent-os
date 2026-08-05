"""Trusted cgroup-before-exec launch gate (M2-B25).

Production resource containment must not rely on a Python ``preexec_fn`` (or an
equivalent child-side ``SIGSTOP`` hook) to pause an already-executing image.  The
ordering enforced here is:

1. the trusted controller obtains the child PID;
2. the child remains behind a trusted pipe gate and has not exec'd the launcher;
3. the controller places the child in the intended real cgroup;
4. the controller verifies membership from the kernel ``cgroup.procs`` file on a
   cgroup2 filesystem (synthetic regular files are refused);
5. the controller releases the gate;
6. only then may the launcher image — and therefore the untrusted command —
   execute.

The gate itself is a pipe: the trusted child blocks in ``read`` before
``execve``.  That is controller-owned trusted code, not a stop-before-exec hook
injected through ``subprocess.Popen(preexec_fn=...)``.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import stat
from typing import Any

from .resource_limits import CGROUP2_SUPER_MAGIC, EffectCgroup, statfs_f_type

LAUNCH_ORDER = (
    "OBTAIN_CHILD_PID",
    "CHILD_BEHIND_TRUSTED_GATE",
    "ATTACH_TO_REAL_CGROUP",
    "VERIFY_KERNEL_MEMBERSHIP",
    "RELEASE_GATE",
    "EXEC_LAUNCHER",
)

# --- M2-B30: the release-state model ----------------------------------------
#
# A gate release is an instruction handed to the trusted helper across a socket.
# An exception raised by the caller therefore answers "did the call finish?",
# never "did the gate open?".  Those are different questions, and conflating
# them produced a claim -- "the command never ran" -- that the controller was
# not in a position to make.
#
# The protocol below separates them.  The helper acknowledges *twice*: once when
# the request has been accepted and the gate write has not yet been attempted,
# and once after the write has either completed or failed.  Which
# acknowledgements arrived is what decides the state:
#
#   no accept frame ................ RELEASE_OUTCOME_UNKNOWN
#   accept, then no completion ..... RELEASE_OUTCOME_UNKNOWN  (ack lost)
#   terminal first frame ........... NOT_RELEASED   (write never attempted)
#   completion says write failed ... NOT_RELEASED
#   completion says written ........ RELEASED

RELEASE_NOT_RELEASED = "NOT_RELEASED"
RELEASE_RELEASED = "RELEASED"
RELEASE_OUTCOME_UNKNOWN = "RELEASE_OUTCOME_UNKNOWN"

RELEASE_STATES = (RELEASE_NOT_RELEASED, RELEASE_RELEASED, RELEASE_OUTCOME_UNKNOWN)

#: Protocol phases, in the order the trusted helper passes through them.
RELEASE_PHASE_NOT_GATED = "NOT_GATED"
RELEASE_PHASE_ALREADY_RELEASED = "ALREADY_RELEASED"
RELEASE_PHASE_REQUEST_NOT_SENT = "RELEASE_REQUEST_NOT_SENT"
RELEASE_PHASE_ACCEPT_FRAME_LOST = "RELEASE_ACCEPT_FRAME_LOST"
RELEASE_PHASE_WRITE_NOT_ATTEMPTED = "RELEASE_WRITE_NOT_ATTEMPTED"
RELEASE_PHASE_ACCEPTED = "RELEASE_ACCEPTED"
RELEASE_PHASE_WRITE_FAILED = "RELEASE_WRITE_FAILED"
RELEASE_PHASE_WRITE_COMPLETED = "RELEASE_WRITE_COMPLETED"
RELEASE_PHASE_ACK_LOST = "RELEASE_ACK_LOST"
RELEASE_PHASE_ACK_AMBIGUOUS = "RELEASE_ACK_AMBIGUOUS"

RELEASE_PHASES = (
    RELEASE_PHASE_NOT_GATED,
    RELEASE_PHASE_ALREADY_RELEASED,
    RELEASE_PHASE_REQUEST_NOT_SENT,
    RELEASE_PHASE_ACCEPT_FRAME_LOST,
    RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
    RELEASE_PHASE_ACCEPTED,
    RELEASE_PHASE_WRITE_FAILED,
    RELEASE_PHASE_WRITE_COMPLETED,
    RELEASE_PHASE_ACK_LOST,
    RELEASE_PHASE_ACK_AMBIGUOUS,
)


@dataclass(frozen=True)
class GateReleaseOutcome:
    """What the controller may truthfully say about one gate release."""

    state: str
    phase: str
    detail: str = ""

    @property
    def released(self) -> bool:
        return self.state == RELEASE_RELEASED

    @property
    def not_released(self) -> bool:
        return self.state == RELEASE_NOT_RELEASED

    @property
    def unknown(self) -> bool:
        return self.state == RELEASE_OUTCOME_UNKNOWN

    @property
    def sentinel_claim(self) -> str:
        """What may be claimed about whether the gated image ran."""

        if self.state == RELEASE_RELEASED:
            return "THE_LAUNCHER_WAS_RELEASED"
        if self.state == RELEASE_NOT_RELEASED:
            return "NO_INSTRUCTION_EXECUTED"
        return "EXECUTION_OUTCOME_UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "release_state": self.state,
            "release_phase": self.phase,
            "release_detail": self.detail,
            "sentinel_claim": self.sentinel_claim,
        }


def classify_release_frames(
    accept_frame: dict[str, Any] | None,
    completion_frame: dict[str, Any] | None,
    *,
    transport_detail: str = "",
) -> GateReleaseOutcome:
    """Decide the release state from what the helper actually acknowledged."""

    if accept_frame is None:
        return GateReleaseOutcome(
            RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACCEPT_FRAME_LOST, transport_detail
        )
    phase = str(accept_frame.get("phase") or "")
    if phase != RELEASE_PHASE_ACCEPTED:
        # The helper answered terminally before touching the gate.
        return GateReleaseOutcome(
            RELEASE_NOT_RELEASED,
            phase or RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
            str(accept_frame.get("error") or ""),
        )
    if completion_frame is None:
        return GateReleaseOutcome(
            RELEASE_OUTCOME_UNKNOWN, RELEASE_PHASE_ACK_LOST, transport_detail
        )
    completion_phase = str(completion_frame.get("phase") or "")
    if completion_phase == RELEASE_PHASE_WRITE_COMPLETED and completion_frame.get("released"):
        return GateReleaseOutcome(RELEASE_RELEASED, RELEASE_PHASE_WRITE_COMPLETED, "")
    if completion_phase == RELEASE_PHASE_WRITE_FAILED:
        return GateReleaseOutcome(
            RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_FAILED, str(completion_frame.get("error") or "")
        )
    # Anything else is a frame this controller does not understand.  It is never
    # read as "nothing happened".
    return GateReleaseOutcome(
        RELEASE_OUTCOME_UNKNOWN,
        RELEASE_PHASE_ACK_AMBIGUOUS,
        f"unrecognised completion frame: {sorted(completion_frame.items())}",
    )


class CgroupLaunchRefused(RuntimeError):
    """The launch gate or cgroup membership proof cannot proceed."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}:{detail}" if detail else code)
        self.code = code
        self.detail = detail


def require_real_cgroup_procs(cgroup_directory: Path) -> Path:
    """Refuse synthetic regular files presented as kernel cgroup evidence."""

    procs = cgroup_directory / "cgroup.procs"
    try:
        info = os.lstat(procs)
    except OSError as error:
        raise CgroupLaunchRefused("cgroup_procs_unreadable", errno.errorcode.get(error.errno, str(error.errno))) from error
    # A hand-made regular file in a temp directory is not kernel evidence.
    # Real cgroup.procs is a cgroupfs virtual file; it is not a directory and on
    # a genuine cgroup2 mount ``statfs`` reports CGROUP2_SUPER_MAGIC.
    f_type = statfs_f_type(cgroup_directory)
    if f_type is not None and f_type != CGROUP2_SUPER_MAGIC:
        raise CgroupLaunchRefused("cgroup_procs_not_on_cgroup2", f"f_type={f_type:#x}")
    if f_type is None:
        # When statfs is unavailable, still reject ordinary regular files that a
        # unit test planted on a normal filesystem directory: they are writable
        # as empty creatable files without the sibling controller files.
        if stat.S_ISREG(info.st_mode) and not (cgroup_directory / "cgroup.controllers").exists():
            raise CgroupLaunchRefused("cgroup_procs_synthetic_regular_file", str(procs))
    return procs


def attach_and_verify_real(cgroup: EffectCgroup, pid: int) -> bool:
    """Attach ``pid`` and prove membership from a real cgroup2 ``cgroup.procs``."""

    if cgroup.path is None:
        return False
    try:
        require_real_cgroup_procs(Path(cgroup.path))
    except CgroupLaunchRefused as error:
        cgroup.attach_error = error.code
        return False
    return cgroup.attach_and_verify(pid)


def gate_child_before_exec(gate_read_fd: int) -> None:
    """Trusted child-side gate: block until the controller releases the pipe.

    This runs only inside trusted helper/controller code, immediately before
    ``execve`` of the launcher.  It is not ``subprocess.Popen(preexec_fn=...)``.
    """

    try:
        while True:
            chunk = os.read(gate_read_fd, 1)
            if chunk:
                break
            # EOF without a release byte means the controller failed closed.
            os._exit(125)
    finally:
        try:
            os.close(gate_read_fd)
        except OSError:
            pass


def release_gate(gate_write_fd: int) -> None:
    """Release a child waiting in :func:`gate_child_before_exec`."""

    try:
        while True:
            written = os.write(gate_write_fd, b"\0")
            if written > 0:
                break
    finally:
        try:
            os.close(gate_write_fd)
        except OSError:
            pass


def launch_order_description() -> dict[str, Any]:
    return {
        "order": list(LAUNCH_ORDER),
        "forbidden_production_constructions": [
            "subprocess.Popen(..., preexec_fn=SIGSTOP_hook)",
            "child-side SIGSTOP as the sole membership gate",
            "synthetic regular file accepted as cgroup.procs evidence",
        ],
        "gate_kind": "trusted_pipe_read_before_execve",
        "membership_evidence": "cgroup2:cgroup.procs",
    }


__all__ = [
    "CGROUP2_SUPER_MAGIC",
    "CgroupLaunchRefused",
    "GateReleaseOutcome",
    "LAUNCH_ORDER",
    "RELEASE_NOT_RELEASED",
    "RELEASE_OUTCOME_UNKNOWN",
    "RELEASE_PHASES",
    "RELEASE_PHASE_ACCEPTED",
    "RELEASE_PHASE_ACCEPT_FRAME_LOST",
    "RELEASE_PHASE_ACK_AMBIGUOUS",
    "RELEASE_PHASE_ACK_LOST",
    "RELEASE_PHASE_ALREADY_RELEASED",
    "RELEASE_PHASE_NOT_GATED",
    "RELEASE_PHASE_REQUEST_NOT_SENT",
    "RELEASE_PHASE_WRITE_COMPLETED",
    "RELEASE_PHASE_WRITE_FAILED",
    "RELEASE_PHASE_WRITE_NOT_ATTEMPTED",
    "RELEASE_RELEASED",
    "RELEASE_STATES",
    "attach_and_verify_real",
    "classify_release_frames",
    "gate_child_before_exec",
    "launch_order_description",
    "release_gate",
    "require_real_cgroup_procs",
]
