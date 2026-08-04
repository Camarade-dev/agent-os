"""The kernel-enforced syscall boundary that closes filesystem IPC.

Milestone 2 claimed that an unshared network namespace plus an absent evidence
path meant no host capability was reachable from the capsule.  That claim is
false.  A pathname ``AF_UNIX`` socket is a *filesystem* object, not a network
object: it is reachable across an unshared network namespace, and ``SCM_RIGHTS``
over such a socket transfers an open file descriptor -- for any file the peer can
open, including one outside the capsule's mount namespace entirely.  A ``FIFO``
in the writable workspace is the same bridge in a simpler form.

Two independent mechanisms close this, because either alone would be a single
point of failure:

1. *This module.*  A seccomp-BPF program is loaded by the launcher immediately
   before the command is executed.  It denies the creation of every ``AF_UNIX``
   socket -- pathname and abstract alike -- and denies ``mknod``/``mknodat``, so
   the command can neither create nor connect an IPC endpoint of any kind.
   Descriptor passing dies with it: ``SCM_RIGHTS`` travels only over an
   ``AF_UNIX`` socket, and no ``AF_UNIX`` descriptor is ever inherited into the
   capsule.
2. *Workspace admission* (:func:`~admissible.paired_runner.effects.scan_workspace_ipc_endpoints`).
   No process is started inside the capsule while the workspace contains a
   socket, FIFO, or device node, so a pre-existing host endpoint is refused
   before the effect boundary rather than merely being unusable.

Why the filter fails closed on the architecture
-----------------------------------------------
Syscall numbers are per-architecture, so a filter written for one ABI is silently
meaningless under another.  A process that can enter a different ABI -- the x32
subset of x86-64 is the classic route -- would otherwise reach the same kernel
services through numbers this program never examines.  The program therefore
begins by comparing ``seccomp_data.arch`` with the exact architecture it was
built for and kills the process on any mismatch, and on x86-64 it also kills any
call whose number carries the x32 bit.  An architecture this module cannot
assemble a filter for is a readiness refusal, never an unfiltered capsule.

The program is assembled here from first principles with :mod:`struct`; it
depends on no third-party library, no compiler, and no network access.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import platform
import struct
from typing import Any


# --- classic BPF ------------------------------------------------------------

_BPF_LD_W_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS
_BPF_JMP_JA = 0x05  # BPF_JMP | BPF_JA
_BPF_JMP_JEQ_K = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
_BPF_JMP_JGE_K = 0x35  # BPF_JMP | BPF_JGE | BPF_K
_BPF_RET_K = 0x06  # BPF_RET | BPF_K

#: Offsets into ``struct seccomp_data``: nr, arch, and the low word of args[0].
_OFFSET_NR = 0
_OFFSET_ARCH = 4
_OFFSET_ARG0_LOW = 16

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

#: ``EPERM``.  A denied call returns an ordinary error the command can observe,
#: so a program that merely *tries* an IPC endpoint fails cleanly instead of
#: dying with a signal that would be indistinguishable from an unrelated crash.
_DENY_ACTION = SECCOMP_RET_ERRNO | 1

#: The x32 ABI marks its syscall numbers with this bit on x86-64.
_X32_SYSCALL_BIT = 0x40000000

AF_UNIX = 1

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7


@dataclass(frozen=True)
class _ArchitectureProfile:
    """The exact syscall numbering one filter is assembled against."""

    machine: str
    audit_arch: int
    socket: int
    socketpair: int
    mknod: int | None
    mknodat: int
    reject_x32: bool


#: Only architectures whose numbering is recorded here can be filtered.  Any
#: other host is a readiness refusal.
_PROFILES: dict[str, _ArchitectureProfile] = {
    "x86_64": _ArchitectureProfile(
        machine="x86_64",
        audit_arch=AUDIT_ARCH_X86_64,
        socket=41,
        socketpair=53,
        mknod=133,
        mknodat=259,
        reject_x32=True,
    ),
    "aarch64": _ArchitectureProfile(
        machine="aarch64",
        audit_arch=AUDIT_ARCH_AARCH64,
        socket=198,
        socketpair=199,
        # aarch64 has no legacy mknod; mknodat is the only entry point.
        mknod=None,
        mknodat=33,
        reject_x32=False,
    ),
}

#: The exact contract this filter enforces, recorded in durable evidence.
SECCOMP_CONTRACT = (
    "Denies socket(AF_UNIX, ...) and socketpair(AF_UNIX, ...) so no pathname or abstract Unix "
    "domain socket can be created, which also removes every route for SCM_RIGHTS descriptor "
    "passing; denies mknod and mknodat so no FIFO or device node can be created inside the "
    "workspace.  A mismatched seccomp_data.arch, and on x86-64 any x32 syscall number, kills the "
    "process.  Every other syscall is allowed; this filter is an IPC boundary, not a policy."
)


class SeccompUnavailable(RuntimeError):
    """No filter can be assembled for this host, so no capsule may be built."""


def _instruction(code: int, jt: int, jf: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def current_profile(machine: str | None = None) -> _ArchitectureProfile:
    """The syscall numbering for this host, or a refusal."""

    name = machine or platform.machine()
    profile = _PROFILES.get(name)
    if profile is None:
        raise SeccompUnavailable(
            f"no seccomp syscall numbering is recorded for the {name} architecture"
        )
    return profile


def build_program(profile: _ArchitectureProfile | None = None) -> bytes:
    """Assemble the ``struct sock_filter[]`` program for this architecture.

    The assembly is written as a symbolic instruction list and the jump offsets
    are resolved afterwards, because a hand-counted classic-BPF offset that is
    wrong by one does not fail loudly -- it silently allows a syscall the filter
    was written to deny.
    """

    profile = profile or current_profile()

    body: list[tuple[Any, ...]] = [
        ("ld", _OFFSET_ARCH),
        # A foreign architecture means these syscall numbers mean something else.
        ("jeq", profile.audit_arch, "next", "kill"),
        ("ld", _OFFSET_NR),
    ]
    if profile.reject_x32:
        body.append(("jge", _X32_SYSCALL_BIT, "kill", "next"))
    if profile.mknod is not None:
        body.append(("jeq", profile.mknod, "deny", "next"))
    body += [
        ("jeq", profile.mknodat, "deny", "next"),
        ("jeq", profile.socket, "domain", "next"),
        ("jeq", profile.socketpair, "domain", "next"),
        ("ja", "allow"),
        ("label", "domain"),
        # Only the domain argument decides; the type and protocol are irrelevant
        # to whether this is a Unix-domain endpoint.
        ("ld", _OFFSET_ARG0_LOW),
        ("jeq", AF_UNIX, "deny", "allow"),
        ("label", "deny"),
        ("ret", _DENY_ACTION),
        ("label", "kill"),
        ("ret", SECCOMP_RET_KILL_PROCESS),
        ("label", "allow"),
        ("ret", SECCOMP_RET_ALLOW),
    ]

    labels: dict[str, int] = {}
    flat: list[tuple[Any, ...]] = []
    for item in body:
        if item[0] == "label":
            labels[item[1]] = len(flat)
            continue
        flat.append(item)

    program = b""
    for position, item in enumerate(flat):
        kind = item[0]

        def offset(target: Any) -> int:
            if target == "next":
                return 0
            distance = labels[target] - (position + 1)
            if not 0 <= distance <= 0xFF:
                raise SeccompUnavailable("the seccomp program does not fit classic BPF jump range")
            return distance

        if kind == "ld":
            program += _instruction(_BPF_LD_W_ABS, 0, 0, item[1])
        elif kind == "ret":
            program += _instruction(_BPF_RET_K, 0, 0, item[1])
        elif kind == "ja":
            program += _instruction(_BPF_JMP_JA, 0, 0, labels[item[1]] - (position + 1))
        elif kind == "jeq":
            program += _instruction(_BPF_JMP_JEQ_K, offset(item[2]), offset(item[3]), item[1])
        elif kind == "jge":
            program += _instruction(_BPF_JMP_JGE_K, offset(item[2]), offset(item[3]), item[1])
        else:  # pragma: no cover - the assembly vocabulary is closed
            raise SeccompUnavailable(f"unknown seccomp instruction {kind}")
    return program


def program_digest(program: bytes | None = None) -> str:
    """The exact identity of the filter, recorded in the capsule manifest."""

    return hashlib.sha256(program if program is not None else build_program()).hexdigest()


def open_program_descriptor(program: bytes | None = None) -> int:
    """Return an inheritable, rewound descriptor holding the filter bytes.

    ``bwrap --seccomp FD`` reads the program from a descriptor.  An anonymous
    in-memory file is used so the filter never exists as a host pathname that
    something else could replace between assembly and load.
    """

    payload = program if program is not None else build_program()
    descriptor = os.memfd_create("admissible-capsule-seccomp", 0)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.set_inheritable(descriptor, True)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def describe() -> dict[str, Any]:
    """The durable description of the filter this host will actually load."""

    profile = current_profile()
    program = build_program(profile)
    return {
        "machine": profile.machine,
        "audit_arch": profile.audit_arch,
        "instruction_count": len(program) // 8,
        "program_sha256": program_digest(program),
        "denied_syscalls": sorted(
            name
            for name, number in (
                ("socket(AF_UNIX)", profile.socket),
                ("socketpair(AF_UNIX)", profile.socketpair),
                ("mknod", profile.mknod),
                ("mknodat", profile.mknodat),
            )
            if number is not None
        ),
        "foreign_architecture_action": "SECCOMP_RET_KILL_PROCESS",
        "denied_action": "SECCOMP_RET_ERRNO(EPERM)",
        "contract": SECCOMP_CONTRACT,
    }


__all__ = [
    "AF_UNIX",
    "AUDIT_ARCH_AARCH64",
    "AUDIT_ARCH_X86_64",
    "SECCOMP_CONTRACT",
    "SECCOMP_RET_ALLOW",
    "SECCOMP_RET_ERRNO",
    "SECCOMP_RET_KILL_PROCESS",
    "SeccompUnavailable",
    "build_program",
    "current_profile",
    "describe",
    "open_program_descriptor",
    "program_digest",
]
