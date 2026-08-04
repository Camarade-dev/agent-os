# M2 Resource Containment Specification

Branch: `paired-runner/m2-causal-index-and-ipc-repairs`
Starting commit: `6383f765520e3d98c7359118704d063b6aa39b52`
Closes: **M2-M18**

## 1. What was wrong

The repaired capsule had filesystem, PID, network, IPC, and UTS namespaces, and
a wall-clock timeout. It had no CPU limit, no memory limit, no process-count
limit, no file-size limit, no descriptor limit, and no core-dump prohibition.

**A PID namespace is a naming boundary, not a quota.** A fork bomb, an allocator,
or a descriptor loop reaches the host long before a wall-clock timeout is the
thing that stops it. The first repair pass disclosed this as a known limitation;
a substrate that calls its effect process untrusted cannot keep it.

## 2. Layers

Two layers, applied in this order of preference. The mechanism actually in force
is recorded in the durable observation.

### `CGROUP_V2_AND_RLIMIT`

When the host delegates a writable cgroup v2 subtree, a per-effect cgroup bounds
the **whole process domain in aggregate**: `pids.max` and `memory.max` apply to
every descendant together rather than to each process individually. The launcher
is held behind a trusted controller launch gate, attached, and
membership-verified from real `cgroup.procs` before the gate is released so the
launcher and untrusted command may exec (see
`implementation/M2_CGROUP_LAUNCH_PRIMITIVE_SPEC.md`; the third-repair
`preexec_fn`/`SIGSTOP` construction is withdrawn). Directory creation alone is
not membership. Attachment failure refuses the effect; when readiness promised
this mechanism, silent degradation to RLIMIT is forbidden. The subtree is
removed only when it has no live members.

`probe_cgroup_delegation()` does not infer delegation from the presence of
`/sys/fs/cgroup`. It resolves this process's own unified path, requires the
`pids` and `memory` controllers, and then **physically creates and removes a real
subtree**. Anything less is reported unavailable.

### `RLIMIT`

Always applied, on every host, and physically probed at readiness.
`_capsule_init.py` applies the bounds in the **forked child, immediately before
`execv`** — the only point at which they bound the command without also bounding
the supervisor. An address-space or process limit imposed on the init itself
would stop it from reaping, and quiescence would become unobservable.

| Bound | Resource | Default |
| --- | --- | --- |
| `max_processes` | `RLIMIT_NPROC` | 64 |
| `max_address_space_bytes` | `RLIMIT_AS` | 2 GiB |
| `max_cpu_seconds` | `RLIMIT_CPU` | `ceil(timeout_ms / 1000) + 30` |
| `max_open_files` | `RLIMIT_NOFILE` | 256 |
| `max_file_size_bytes` | `RLIMIT_FSIZE` | 1 GiB |
| `core_dump_bytes` | `RLIMIT_CORE` | 0 |

Every bound is set with soft and hard equal, so nothing can raise it back. The
sole exception is `RLIMIT_CPU`, whose hard limit is deliberately one second later
than its soft limit: the soft limit raises `SIGXCPU` and the hard limit `SIGKILL`s,
and that ordering is what makes the escalation observable rather than abrupt.

The bounds are fixed constants at this milestone. A per-request bound would be a
policy input, and this substrate contains no policy. The CPU bound is derived
from the request's own timeout because a command may legitimately use every
second it asked for across several cores.

The bounds reach the capsule as one canonical JSON argument on the init's command
line, because this package is not mounted inside the capsule and cannot be
imported there.

## 3. Enforcement is observed, not asserted

After setting each bound the child calls `getrlimit` and reports **what the
kernel actually holds** back to the init through the pre-exec pipe; the init
places it in the status document. `ResourceObservation` therefore records:

* `containment_mechanism` — `CGROUP_V2_AND_RLIMIT`, `RLIMIT`, or `NONE`;
* `containment_availability` — `OBSERVED` only when the init reported enforced
  bounds; `NOT_MEASURED` otherwise, never the values that were merely requested;
* `containment_bounds` — the effective values read back from the kernel, plus any
  cgroup limits actually written;
* `containment_semantics` — what the recorded mechanism does and does not cover.

A bound that could not be set is fatal to the child: the command never runs.
Running with one limit silently missing would make the durable observation a
false statement about what contained the effect.

## 4. Readiness refuses rather than degrading

`probe_capsule_readiness` runs the **real init**, with the **real bounds
argument**, inside a real capsule, and requires the kernel to stop an unbounded
consumer:

* a fork loop must fail with `EAGAIN` before 200 processes;
* a 1 GiB allocation must raise `MemoryError`;
* a descriptor loop must fail with `EMFILE` before 4096 descriptors;
* the init's status document must report `resource_limits_applied`.

Any failure is `SandboxUnavailable` before any proposal is published. There is no
silent fallback to an unbounded process domain.

## 5. Test matrix

`tests/test_admissible_paired_runner_m2_second_repairs.py::ResourceContainmentTests`

| Requirement | Test |
| --- | --- |
| fork bomb | `test_a_fork_bomb_is_bounded` |
| memory allocation | `test_a_memory_allocation_is_bounded` |
| descriptor exhaustion | `test_descriptor_exhaustion_is_bounded` |
| large file / disk attempt | `test_a_large_file_write_is_bounded` |
| timeout plus resource kill | `test_a_cpu_loop_is_stopped_by_the_requested_timeout` |
| effective bounds recorded durably | `test_the_effective_bounds_are_recorded_in_the_durable_observation` |
| no effect on unrelated host processes | `test_an_unrelated_host_process_is_untouched` |
| the mechanism in force is recorded honestly | `test_readiness_records_the_mechanism_actually_in_force` |

## 6. Qualification host

On the qualification host (`Linux 6.18.33.2-microsoft-standard-WSL2`,
CPython 3.12.3) `/sys/fs/cgroup` is not writable by the running user and no
subtree is delegated, so `probe_cgroup_delegation()` reports unavailable and the
mechanism in force is `RLIMIT`. That is recorded, not papered over: the
observation says `RLIMIT`, and `containment_semantics` states plainly that
aggregate accounting is unavailable on this host and that containment is the
per-process `setrlimit` layer, physically proved at readiness.

## 7. Stated limitations

* `RLIMIT_NPROC` is enforced per user ID within the capsule's user namespace, so
  it bounds the process domain but is not an aggregate cgroup accounting. Where a
  cgroup is delegated, the aggregate layer is added on top rather than replacing
  this one.
* `RLIMIT_AS` bounds address space, not resident set. A command that maps far more
  than it touches is bounded by the mapping, which is the conservative direction.
* Disk *space* is not bounded; `RLIMIT_FSIZE` bounds any single file. A workspace
  quota would be a filesystem-level control this milestone does not implement.
* Child CPU and peak RSS in `ResourceObservation` remain `OBSERVED_BEST_EFFORT`
  because `getrusage(RUSAGE_CHILDREN)` aggregates every reaped child of the
  controller. The *bounds* are `OBSERVED`; the *measurements* are not.
