# M2 Cgroup Launch Primitive Specification

Branch: `paired-runner/m2-fourth-critical-repair-retry`
Starting commit: `1133d131c75ed07e79d949b6b3f2f40847a3218b`
Closes: **M2-B25**

## 1. Defect

The production path used `subprocess.Popen(..., preexec_fn=SIGSTOP)`. That is a
Python child-side stop-before-exec hook. It is not an auditable trusted launch
gate, and it deadlocks any parent that blocks on the child’s stdio before
`SIGCONT`.

## 2. Required ordering

1. Trusted controller obtains the child PID.
2. Child remains behind a trusted pipe gate and has not exec’d the launcher.
3. Controller places the child in the intended real cgroup.
4. Controller verifies membership from kernel `cgroup.procs` on a cgroup2
   filesystem (synthetic regular files are refused).
5. Controller releases the gate.
6. Launcher and command may execute.

## 3. Production construction

- Module: `admissible/paired_runner/cgroup_launch.py`
- Gate: trusted `read` on a pipe immediately before `execve` inside the mount
  helper (`gate_child_before_exec` / `release_gate`).
- Forbidden in production: `preexec_fn`, child-side `SIGSTOP` as the membership
  gate, synthetic `cgroup.procs` files on ordinary directories.
- Spawn lives in `PrivateMountHelper` so the private tmpfs bind and the launch
  gate share one trusted helper.

## 4. Physical qualification rule

Verified closure requires a real delegated cgroup v2 subtree and
kernel-observed membership through this production path. When the environment
cannot provide that, the disposition is
`IMPLEMENTED_NOT_PHYSICALLY_QUALIFIED` or `REFUSED` — never a skipped test
labelled verified.

## 5. Tests

`tests/test_admissible_paired_runner_m2_fourth_repairs.py::LaunchGateConstructionTests`

---

# Addendum: cgroup topology repair (M2-B25 closure)

Branch: `paired-runner/m2-b25-cgroup-topology-repair`
Starting commit: `f2e766fe1ed1c3ac60f4cf542a6e5e7723e72b77`

## A1. Residual defect

The launch *ordering* above was correct, but it could never be reached on a
delegated host. `probe_cgroup_delegation()` proved only that an empty child
directory could be created and removed inside the delegated cgroup, and then
reported `available=true`. The delegated service cgroup still contained the
trusted controller process, so cgroup v2's no-internal-process constraint
forbade it from distributing `memory` or `pids` to any child. The first real
`EffectCgroup.create()` therefore failed with `EACCES` long after readiness had
promised `CGROUP_V2_AND_RLIMIT`:

```
{"effect_create_error": "EACCES", "effect_created": false,
 "parent_cgroup_controllers": "cpuset cpu io memory pids",
 "parent_cgroup_procs": "45657", "parent_cgroup_subtree_control": ""}
```

Readiness and execution disagreed. That is what this repair makes impossible.

## A2. Required topology

```
delegated systemd/service cgroup            <- the effect parent
|-- admissible-manager-<pid>                <- trusted manager leaf
|   `-- the trusted paired-runner controller process (and its trusted helpers)
`-- admissible-effect-<label>                <- one sibling per effect
    `-- the gated launcher / command process tree
```

Effects are **siblings** of the manager leaf and are never created beneath it.
The delegated parent is retained as the effect parent; the manager leaf is
retained as the trusted controller's cgroup.

## A3. Bootstrap sequence

Implemented by `resource_limits.initialize_cgroup_topology()`:

1. resolve `/proc/self/cgroup`'s unified entry and bind it to the real
   `/sys/fs/cgroup` cgroup2 mount (`statfs` must report `CGROUP2_SUPER_MAGIC`);
2. require the real `memory` and `pids` controllers in `cgroup.controllers`;
3. create a unique manager leaf, refusing a collision rather than adopting one;
4. move **only** the current controller process into it;
5. verify the move from kernel state (`cgroup.procs` and `/proc/self/cgroup`);
6. verify the delegated parent retains no processes — unrelated processes are
   refused, never moved;
7. write `+memory +pids` to the parent's `cgroup.subtree_control`;
8. read `cgroup.subtree_control` back and require both controllers.

Every transition has a classified failure code and, where rollback is
physically safe, restores the prior state and removes the owned empty cgroup.
Where rollback is not safe the truthful state is preserved and reported
(`controller_returned=`, `manager_leaf_removed=`) and all effects are refused.

## A4. Classified outcomes

`NO_UNIFIED_CGROUP_V2`, `CGROUP2_NOT_MOUNTED`, `DELEGATED_PATH_MISSING`,
`DELEGATED_PATH_NOT_CGROUP2`, `CONTROLLERS_UNREADABLE`, `MISSING_CONTROLLERS`,
`MANAGER_LEAF_COLLISION`, `MANAGER_LEAF_CREATE_FAILED`,
`CONTROLLER_MOVE_FAILED`, `CONTROLLER_MOVE_NOT_OBSERVED`,
`PARENT_STILL_POPULATED`, `SUBTREE_CONTROL_WRITE_FAILED`,
`SUBTREE_CONTROL_UNREADABLE`, `CONTROLLER_READBACK_MISMATCH`,
`EFFECT_CREATE_FAILED`, `EFFECT_COLLISION`, `INVALID_LABEL`,
`LIMIT_WRITE_FAILED`, `LIMIT_READBACK_MISMATCH`, `STALE_CACHED_TOPOLOGY`,
`TOPOLOGY_NOT_INITIALIZED`, and the single success `INITIALIZED`.

## A5. Idempotence and process identity

The topology cache is bound to the owning PID, the controller's unified cgroup,
the effect parent, and the manager-leaf identity. A repeated call re-derives all
four from kernel state. A cache inherited across `fork()` is never trusted by a
different PID, and a stale, missing, or replaced manager path fails closed with
`STALE_CACHED_TOPOLOGY` rather than being silently re-bootstrapped. A process
that is already a member of a manager leaf reuses it: no leaf is nested, and the
leaf is never reinterpreted as a new delegated parent.
`process_supervision.cgroup_delegation()` carries the same PID binding.

## A6. Probe semantics

`probe_cgroup_delegation()` no longer means "mkdir succeeded". It bootstraps or
reuses the topology, creates a real probe effect cgroup, writes `pids.max` and
`memory.max`, reads both back, compares them exactly (`max` is refused as a
finite bound), and removes the probe cgroup. `available=true` is a statement
about that completed rehearsal, and the returned evidence carries the classified
code, the manager leaf, the enabled controllers, and the observed probe limits.

## A7. Lifecycle

`topology_lifecycle_description()` is the durable statement. The manager leaf
holds the live controller and is therefore **not** removed by this process; it
is reclaimed when the containing delegated service or transient systemd unit is
torn down. That is a disclosed residual cgroup, explicitly not a leak-free
manual removal. Per-effect cgroups are removed after their process trees are
quiescent, and removal is never reported as success while `cgroup.procs` still
lists live members. No cgroup this process did not create is ever mutated or
removed.

## A8. Tests

`tests/test_admissible_paired_runner_m2_b25_cgroup_topology.py` — deterministic
fault coverage of every transition above, plus delegated physical tests that
drive the production `SharedEffectSubstrate` path. Under
`ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1` the physical tests fail rather than
skip; a skipped delegated test is a closure failure.

# Addendum B: final fail-closed repair (M2-B28, M2-B29, M2-B30)

Normative. This addendum extends, and does not replace, Addendum A.

## B1. Probe cleanup truthfulness (M2-B28)

`probe_cgroup_delegation()` may construct a positive result only after all of
the following have completed **and been observed**:

1. the manager topology was initialized or revalidated;
2. a real probe-effect cgroup was created;
3. `pids.max` was written and read back exactly;
4. `memory.max` was written and read back exactly;
5. the probe cgroup was observed to hold no members;
6. the owned probe cgroup was removed;
7. the probe path was observed to be absent.

Removal failure returns a refused, classified result carrying the exact errno
and whether a residual path exists. `PROBE_NOT_EMPTY`, `PROBE_CLEANUP_FAILED`,
`PROBE_RESIDUAL_PATH`, and `PROBE_DISAPPEARED` are the classifications. `ENOENT`
is `PROBE_DISAPPEARED`: this controller created the probe and did not remove it,
so its disappearance is not evidence of a safe, expected removal. The word
"removed" is produced only by verified absence. No unowned cgroup is created,
mutated, or removed on any path.

## B2. Cached-topology revalidation (M2-B29)

Before a cached topology or a cached delegation result is reused for a
production effect or a positive readiness answer, the following are re-derived
from the kernel: owner PID identity; existence of the manager leaf and the
effect parent; `dev:ino` identity of both, so a directory removed and recreated
under the same name is refused; the manager leaf is still a child of the effect
parent; the controller is still a member of the manager leaf; both directories
are still on a cgroup2 filesystem; the controller's **full** unified path from
`/proc/self/cgroup` — never the basename — equals the recorded path; the
delegated effect parent holds no processes; `cgroup.controllers` still offers
`memory` and `pids`; `cgroup.subtree_control` is readable and still enables
them; and no cached controller set has regressed.

Any contradiction returns `STALE_CACHED_TOPOLOGY` with a precise reason. The
refusal is cached: nothing is silently re-bootstrapped, no process is moved, no
controller is re-enabled, no effect cgroup is created, and a promised
`CGROUP_V2_AND_RLIMIT` is never downgraded to `RLIMIT`. A cache inherited across
`fork()` is never reused by the child.

## B3. Release-state model (M2-B30)

The trusted helper acknowledges a gate release **twice**: once when the request
has been accepted and the write has not yet been attempted, and once after the
write completed or failed. The controller derives exactly one of:

| observation | state |
| --- | --- |
| terminal first frame (`RELEASE_WRITE_NOT_ATTEMPTED`) | `NOT_RELEASED` |
| completion frame reports the write failed | `NOT_RELEASED` |
| completion frame reports the write completed | `RELEASED` |
| accept frame not received | `RELEASE_OUTCOME_UNKNOWN` |
| accept received, completion lost | `RELEASE_OUTCOME_UNKNOWN` |
| unrecognised completion frame | `RELEASE_OUTCOME_UNKNOWN` |

`release()` does not raise on a protocol failure: an exception cannot say which
side of the write it came from. Gate-before-exec ordering, membership
verification before the release request, and the nominal successful release are
unchanged. No untrusted acknowledgement exists: only the trusted helper speaks
this protocol.

## B4. Bounded cleanup on refusal or ambiguity

On `NOT_RELEASED` and on `RELEASE_OUTCOME_UNKNOWN` alike, the effect is refused,
completion and export are refused, and `abort_gated_effect` runs: the effect
cgroup is used as a kill domain (`cgroup.kill` where the kernel offers it,
otherwise `SIGKILL` to exactly its observed members and to nothing else); the
owned launcher is killed and reaped; every owned descriptor and pipe is closed;
quiescence is awaited under a bounded timeout; the owned per-effect cgroup is
removed and its absence verified, or its residual state is recorded truthfully.
Cleanup is idempotent: a repeated call removes nothing further and reports no
second success.

Under `RELEASE_OUTCOME_UNKNOWN` the evidence states
`EXECUTION_OUTCOME_UNKNOWN`. It is never claimed that the sentinel is absent or
that no instruction executed. The guaranteed properties there are: no successful
completion or export, bounded termination, no live process leak, no descriptor
leak, no per-effect cgroup leak, and truthful ambiguity evidence.

## B5. Tests

`tests/test_admissible_paired_runner_m2_b25_final_failclosed.py` covers every
case above deterministically and adds delegated physical qualification for the
probe absence, revalidated repeated effects, the pre-release refusal, the lost
acknowledgement, the nominal release, and cleanup idempotence.
