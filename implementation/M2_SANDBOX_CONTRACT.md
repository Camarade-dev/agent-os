# M2 Sandbox Contract

The one Linux capsule every paired-runner effect process executes inside.

Implemented by `admissible/paired_runner/sandbox.py` and
`admissible/paired_runner/_capsule_init.py`, driven by
`admissible/paired_runner/process_supervision.py`.

---

## 1. Why this exists

The Milestone 2 command path was a bare `subprocess.Popen` whose only
restriction was its working directory. A working directory restricts nothing:
a typed command may name any absolute host path. The audit finding (M2-R01) was
therefore not that the sandbox was weak but that there was no sandbox. In
particular the effect process could open and rewrite the durable evidence store
that is supposed to be the independent record of what it did.

**An effect process that can edit its own evidence is not observed; it is
trusted.** This contract removes that trust.

## 2. Governing principle

The effect process is untrusted. Nothing in this contract depends on the
command choosing to behave. Specifically, the boundary does **not** rely on:

- the secrecy of any evidence path;
- cooperative command behaviour;
- same-user file permissions;
- prompt restrictions;
- a command declining to use absolute paths;
- descendants remaining in their original process group.

Every guarantee below is enforced by the kernel and would survive a command
written specifically to break it.

## 3. Mechanism and provenance

| Property | Value |
| --- | --- |
| Mechanism | `bubblewrap` (`bwrap`) |
| Kind | boundary launcher, not an in-process restriction |
| In-capsule init | `admissible/paired_runner/_capsule_init.py`, run as PID 1 |
| Shared by | the future DIRECT and GOVERNED modes, identically |

The construction follows the approved strong-canary boundary-launcher
provenance, element for element:

1. **Canary boundary launcher.** The boundary is a separate launcher process
   that constructs the namespaces before the effect exists, rather than a
   restriction applied from inside the effect's own process, which the effect
   could undo.
2. **Bubblewrap / mount-namespace construction.** The workspace is bind-mounted
   at exactly one fixed internal path and nothing else of the host filesystem is
   named.
3. **Private process namespace with init and reaping.** `--unshare-pid`
   plus `--as-pid-1` makes our init PID 1, so every orphan reparents to it.
4. **Network isolation.** `--unshare-net`, an unshared network namespace — not
   a filter the command could route around.
5. **Descriptor and evidence-root separation.** The process-domain observation
   travels on a dedicated descriptor the effect does not hold, and the evidence
   root is never mounted at all.

**There is exactly one implementation and no mode receives a different one.**
The condition (DIRECT or GOVERNED) is not an input to any function in
`sandbox.py`.

## 4. The capsule construction

Exact launcher flags, from `capsule_argv`:

```
--unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts
--unshare-cgroup-try
--clearenv --die-with-parent --new-session --as-pid-1
--proc /proc  --tmpfs /tmp  --dev /dev
--ro-bind-try <each toolchain input> <same path>
--bind  <workspace host path>  /workspace
--ro-bind <capsule init source> /.admissible-capsule-init
--setenv <name> <value>   (for each entry of CAPSULE_ENVIRONMENT)
--chdir /workspace[/<relative cwd>]
-- <interpreter> /.admissible-capsule-init <status fd> <control fd> <timeout ms> <argv...>
```

### 4.1 Filesystem

| Requirement | How it is met |
| --- | --- |
| Workspace at one fixed internal path | `--bind <host> /workspace`; `CAPSULE_WORKSPACE_PATH` is the only writable host object |
| Only explicitly required runtime/toolchain inputs | `CAPSULE_TOOLCHAIN_INPUTS` = `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32`, each read-only |
| Evidence root never exposed | It is absent from the mount namespace; `build_capsule_specification` refuses any construction where the evidence root is the workspace, inside it, or inside an exposed toolchain input |
| Private `/tmp` | `--tmpfs /tmp` |
| Private `/proc` | `--proc /proc` over a private PID namespace |
| No host `/home`, no arbitrary `/tmp`, no parent paths | none of them are bound, so no name for them exists |
| No host credentials | `/etc` is deliberately **not** in the toolchain list, so `/etc/passwd`, `/etc/shadow`, and resolver configuration are absent |

`/etc` and `/home` are excluded by omission. This matters: the refusal a
command observes is `ENOENT`, not `EACCES`. The path does not exist in its
namespace, so no permission model has to hold.

### 4.2 Process domain

- `--unshare-pid` gives a private PID namespace.
- `--as-pid-1` makes `_capsule_init.py` the namespace init, so every orphan,
  `setsid` escapee, and double-forked descendant reparents to it.
- Quiescence is derived inside the capsule from `ECHILD` — the kernel returns
  it only when no process other than init remains. It is a kernel observation,
  never an assertion.
- `os.kill(-1, sig)` inside the namespace is the exact "terminate the whole
  process domain" primitive. The namespace, not the process group, is the
  boundary.
- `--die-with-parent` means the capsule cannot outlive its supervisor. If the
  supervisor dies, the kernel tears down the namespace and every descendant
  with it.

### 4.3 Network

Disabled by default via `--unshare-net`. `build_capsule_specification` accepts a
`network_enabled` field so a future policy field has an exact place to land, and
**Milestone 2 refuses it**: `SandboxUnavailable` is raised. Enabling it in a
later milestone must still be an explicit construction, never the inheritance of
an ambient host network namespace.

### 4.4 Credentials and environment

`--clearenv` discards the controller's entire environment inside the capsule.
The environment is then rebuilt from nothing out of `CAPSULE_ENVIRONMENT`:

```
PATH=/usr/bin:/bin   HOME=/workspace   PWD=/workspace
LANG=C.UTF-8   LC_ALL=C.UTF-8   TZ=UTC   TMPDIR=/tmp
```

No credential, token, provider variable, or host `HOME` can be inherited,
because nothing is inherited.

### 4.5 Descriptors

| Descriptor | Held by | Purpose |
| --- | --- | --- |
| `stdout`, `stderr` | the effect | bounded, fingerprinted output |
| status fd | init only; **closed in the effect** | the one exact process-domain observation |
| control fd | init only; **closed in the effect** | cancellation, signalled by the controller closing its write end |

Because the effect never holds the status descriptor, it cannot forge,
suppress, or race the process-domain observation by writing to its own output.

## 5. Readiness: refuse, never fall back

`probe_capsule_readiness()` constructs a **real** throwaway capsule and requires
the kernel to demonstrate each isolation:

- `/home` absent;
- `/etc/passwd` absent;
- `/proc/self` present (private `/proc`);
- `/tmp` on a different device than `/usr`, and empty (private `/tmp`);
- an outbound connect fails with `ENETUNREACH` (network unshared).

A present `bwrap` binary on a host with unprivileged user namespaces disabled
would otherwise be mistaken for a working boundary, so this is a physical probe
rather than a version check.

If the probe fails, `SandboxUnavailable` is raised during readiness — **before
any proposal is published and therefore before any effect boundary exists.**

> An unsandboxed `Popen` is not a degraded capsule. It is the absence of the
> boundary this milestone exists to provide. There is no fallback path in the
> code, and `_run_command` has no branch that can reach `subprocess.Popen`
> without a capsule specification.

Readiness is additionally re-checked during `SharedEffectSubstrate.preflight`,
so a substrate whose capsule became unusable refuses before publication rather
than at the effect.

## 6. The escape matrix

Every row is exercised by `tests/test_admissible_paired_runner_m2_repairs.py`
(`SandboxEscapeMatrixTests`) and is physically refused or isolated.

| Attempt | Result |
| --- | --- |
| absolute-path read of the evidence root / `/etc/passwd` | `ENOENT` — no such name in the namespace |
| absolute-path write into the evidence root | `ENOENT`; evidence bytes unchanged |
| `../` traversal through process APIs | lands on the capsule root; no host path reachable |
| `/proc` discovery of the controller | only PIDs 1 and 2 exist; the controller is invisible |
| evidence-root access by filesystem walk | no evidence file is found anywhere |
| host `HOME` access | `/home` absent; `HOME=/workspace` |
| arbitrary host `/tmp` access | private tmpfs; host marker invisible |
| network connection | `ENETUNREACH` |
| spawning a detached descendant | contained; cannot mutate the workspace afterwards |
| double fork | contained, detected, reaped |
| `setsid` | contained; the namespace is the boundary, not the group |
| evidence corruption from inside | every pre-existing object is byte-identical afterwards |

## 7. Git observation runs no process at all

Superseded. `observe_git` no longer executes anything: the observer parses refs,
the index, and object storage directly. See
`implementation/M2_SECOND_CRITICAL_REPAIR_REPORT.md`, ADR-M2S-02, and
`NonExecutingGitObserverTests`. The previous construction — running `git` inside
this capsule behind a list of `-c` overrides — was shown to be unclosable,
because a repository names an arbitrary filter driver that `git status` must run.

## 8. Filesystem IPC is closed at the syscall

**Correction.** This contract previously stated that an unshared network
namespace plus an absent evidence path meant no host capability was reachable.
**That statement was false and is withdrawn.** A pathname `AF_UNIX` socket is a
filesystem object: it crosses an unshared network namespace, and `SCM_RIGHTS`
over it transfers an open descriptor for any file the peer can open. A FIFO in
the writable workspace is the same bridge.

The enforced property is now:

> The command sees no host-backed IPC endpoint, and cannot create an IPC endpoint
> visible to a host process during execution.

Two independent mechanisms, neither depending on the other:

1. **A seccomp-BPF syscall boundary** (`--seccomp`), denying `socket(AF_UNIX)`,
   `socketpair(AF_UNIX)`, `mknod`, and `mknodat` with `EPERM`. `SCM_RIGHTS` needs
   no rule of its own: it travels only over an `AF_UNIX` socket, and none can be
   created or inherited. A mismatched `seccomp_data.arch`, and on x86-64 any x32
   syscall number, kills the process.
2. **Workspace admission**: no capsuled process starts over a workspace holding a
   socket, FIFO, or device node, refused before the durable `STARTED` record.

Full detail: `implementation/M2_WORKSPACE_IPC_ISOLATION_SPEC.md`.

## 9. The process domain is bounded, not merely timed

A PID namespace is a naming boundary, not a quota. Every command runs under
kernel-enforced bounds on processes, address space, CPU seconds, open files, and
file size, with core dumps prohibited, applied inside the capsule immediately
before `execv`; a per-effect cgroup v2 subtree is added where the host delegates
one. The effective bounds are read back with `getrlimit` from inside the bounded
child and recorded in the durable resource observation. Readiness physically
proves the bounds before any effect is permitted.

Full detail: `implementation/M2_RESOURCE_CONTAINMENT_SPEC.md`.

## 10. The capsule is identified by its bytes

`CapsuleRuntimeManifest` binds the launcher's path, SHA-256, device, inode,
owner, mode, size, and version; the interpreter's and the in-capsule init's
identities; the seccomp program's digest and architecture; a source identity over
every module of this package; the declared toolchain roots; and the namespace,
mount, and containment contract. It is rechecked before the proposal that
authorises an effect is published, including re-resolving the launcher through
`PATH`, so a replacement or a shadowing entry refuses rather than being recorded
as the capsule that was probed.

## 11. What this contract does not claim

- It does not claim protection against a kernel vulnerability in namespace,
  seccomp, or cgroup isolation itself.
- It does not claim that the workspace stops being a shared host directory. It is
  the one authorised writable surface; admission proves no IPC endpoint exists
  when a process starts and the syscall boundary proves the command cannot create
  one, but a host process acting on the workspace mid-execution is outside both.
- It does not claim aggregate process-domain accounting on a host that delegates
  no cgroup v2 subtree. The mechanism actually in force is recorded in every
  resource observation.
- It does not claim a disk-space quota; `RLIMIT_FSIZE` bounds any single file.
- It does not claim any installed-path or production behaviour. Every effect in
  this milestone happens under a disposable test root.
