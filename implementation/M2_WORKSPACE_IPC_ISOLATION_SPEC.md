# M2 Workspace IPC Isolation Specification

Branch: `paired-runner/m2-causal-index-and-ipc-repairs`
Starting commit: `6383f765520e3d98c7359118704d063b6aa39b52`
Closes: **M2-B12**

## 1. The corrected statement

The Milestone 2 sandbox contract asserted:

> an unshared network namespace plus an absent evidence path means no host
> capability is reachable

**That statement is false, and it is withdrawn.**

`--unshare-net` isolates the *network* namespace. A pathname `AF_UNIX` socket is
not a network object: it is a filesystem object, and it is reachable across an
unshared network namespace by any process that can name its path. Linux further
permits `SCM_RIGHTS` over such a socket, which transfers an *open file
descriptor* — for any file the peer can open, including one that does not exist
anywhere in the capsule's mount namespace. A FIFO in the writable workspace is
the same bridge without the descriptor passing; a device node is a direct host
object.

The premise is reproduced physically, not argued, in
`tests/test_admissible_paired_runner_m2_second_repairs.py::WorkspaceIpcBridgeTests::test_the_kernel_really_does_carry_unix_sockets_across_a_network_namespace`:
a host server binds a pathname socket, a client under `unshare -Urn` connects to
it, and bytes cross. The independent audit demonstrated the same thing, including
the `SCM_RIGHTS` transfer of a descriptor for a file outside the namespace.

## 2. The property this specification enforces

> The command sees no host-backed IPC endpoint, and cannot create an IPC
> endpoint visible to a host process during execution.

## 3. The chosen design

The audit permitted two directions. This repair takes the second, which the audit
allows *only* if it uses a kernel-enforced syscall boundary that blocks pathname
and abstract Unix IPC and `SCM_RIGHTS`, and proves that child-created IPC
endpoints are not host-visible. Both conditions are met, and the proof of the
second is stronger than "not visible": **no child-created IPC endpoint can
exist at all.**

The alternative — materialising a private per-effect workspace and exporting a
validated diff — was considered and rejected for this milestone. It depends on
unprivileged overlayfs being available (it is not guaranteed), and its export
step introduces a large new correctness surface (whiteouts, hard links, modes,
atomicity, partial application) between the effect and the evidence. Since the
required property can be enforced by the kernel directly, at the syscall, adding
a diff-and-apply stage between an untrusted effect and the workspace would trade
a closed boundary for a larger one.

Two **independent** mechanisms enforce the property. Neither depends on the other
being correct.

### Mechanism 1 — the seccomp syscall boundary

`admissible/paired_runner/capsule_seccomp.py` assembles a classic-BPF seccomp
program with `struct` alone — no compiler, no third-party library, no network.
`bwrap --seccomp FD` loads it immediately before the command is executed, so it
applies to the command and every descendant.

Denied, with `SECCOMP_RET_ERRNO(EPERM)`:

| syscall | condition | what it closes |
| --- | --- | --- |
| `socket` | `domain == AF_UNIX` | pathname *and* abstract Unix sockets |
| `socketpair` | `domain == AF_UNIX` | the other route to an `AF_UNIX` descriptor |
| `mknod` | always | FIFO and device creation |
| `mknodat` | always | the same, at a directory descriptor |

`SCM_RIGHTS` needs no rule of its own: it travels only over an `AF_UNIX` socket.
With no way to create one, and with no `AF_UNIX` descriptor ever inherited into
the capsule — the launcher passes only `stdin` (`/dev/null`), the two output
pipes, and the status/control pipes, and the in-capsule init closes the status
and control descriptors in the child before `execv` — there is no route by which
a descriptor can enter or leave.

**Architecture is fail-closed.** Syscall numbers are per-ABI, so a filter written
for one architecture is meaningless under another. The program's first
instruction compares `seccomp_data.arch` against the exact architecture the
filter was assembled for and returns `SECCOMP_RET_KILL_PROCESS` on any mismatch;
on x86-64 it also kills any call carrying the x32 syscall bit. An architecture
this module has no recorded numbering for is a **readiness refusal**
(`SeccompUnavailable`), never an unfiltered capsule.

The filter travels as an anonymous `memfd`, so it never exists as a host pathname
that something could replace between assembly and load. Its SHA-256 is recorded
in the capsule runtime manifest and in the capsule descriptor.

### Mechanism 2 — workspace admission

No process is started inside the capsule while the workspace contains a socket,
FIFO, or device node. `scan_workspace_ipc_endpoints` walks the tree with `lstat`
only — it never opens anything, so a hostile FIFO cannot block the scanner — and
`require_no_workspace_ipc_endpoints` refuses when it finds one.

The refusal happens in `prepare_effect`, which runs **before** the durable
`STARTED` record exists. A workspace carrying an endpoint therefore produces a
`REFUSED` receipt with `error_code = workspace_contains_a_host_ipc_endpoint`,
`effect_crossed_boundary = false`, and no effect at all.

If the scan hits its entry bound, the limit itself is reported as an endpoint:
an unscanned subtree could hold exactly the object the scan exists to find, so a
partial scan never admits.

### Why both

Mechanism 1 alone would leave a pre-existing host socket *present* in the
workspace (unusable, but present, and visible to the observation). Mechanism 2
alone would be a time-of-check race and could not see an abstract socket, which
has no filesystem entry. Together: nothing to connect to, and nothing that can
connect.

## 4. Evidence recorded

`FilesystemObservation` now types special inodes exactly — `socket`, `fifo`,
`block_device`, `character_device`, `other` — rather than lumping them under
`other`, and carries `ipc_endpoint_count` and `ipc_endpoints`, each endpoint
named rather than merely counted. The `AFTER_EFFECT` observation is therefore the
durable proof that no endpoint was exported: `ipc_endpoint_count == 0`.

`CapsuleSpecification` records `seccomp_program_sha256`,
`unix_domain_sockets_denied`, and `special_file_creation_denied`, so the capsule
descriptor fingerprint covers the boundary that was in force.

## 5. Readiness

`probe_capsule_readiness` constructs a real capsule and requires the kernel to
demonstrate, from inside it, that:

* `socket(AF_UNIX, SOCK_STREAM)` fails with `EPERM`;
* `socketpair()` fails with `EPERM`;
* `mkfifo` fails with `EPERM`;

alongside the pre-existing isolation assertions. A seccomp program the kernel
silently failed to load is a readiness refusal, not a degraded capsule.

## 6. Test matrix

`tests/test_admissible_paired_runner_m2_second_repairs.py`

| Requirement | Test |
| --- | --- |
| host pathname Unix server socket under the source workspace | `test_a_host_server_socket_cannot_be_reached_from_inside_the_capsule` |
| abstract Unix socket | `test_an_abstract_unix_socket_cannot_be_created_inside_the_capsule` |
| `SCM_RIGHTS` passing a descriptor for an outside file | `test_socketpair_and_therefore_scm_rights_are_unavailable`, and the server in the test above sends one that is never received |
| host FIFO endpoint | `test_a_host_fifo_in_the_workspace_is_refused_before_the_effect` |
| child-created Unix socket with a host client | `test_a_pathname_unix_socket_cannot_be_created_inside_the_capsule` |
| special inode in the initial snapshot | `test_a_special_inode_in_the_initial_snapshot_is_named_by_the_admission_scan` |
| no exported socket, FIFO, or device | `test_no_socket_fifo_or_device_is_exported_by_an_effect` |
| ordinary regular-file effects remain correct | `test_ordinary_regular_file_effects_remain_correct` |
| the filter itself is well formed and fails closed | `SeccompProgramTests` |

## 7. Third-repair correction

The limitation previously stated here — that a host FIFO created mid-execution
is outside both mechanisms — is **withdrawn as an accepted limitation**. It was
the defect tracked as **M2-B21**. The third repair replaces the live writable
bind with a private per-effect execution view and a trusted export. See
`implementation/M2_PRIVATE_WORKSPACE_EXPORT_SPEC.md` and ADR-M2T-01.

Remaining deliberate capability reductions:

* Denying every `AF_UNIX` socket is a deliberate capability reduction. A command
  that needs local socket IPC will fail with `EPERM`. Milestone 2 is provider-free
  and this is the documented contract of the capsule, not a defect.
* `AF_INET` socket *creation* is still permitted; the unshared network namespace
  is the mechanism that makes it useless, and that is tested separately.
