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

---

# C. Final protocol and process-lifecycle repair (M2-B32, M2-B33, M2-B34)

## C1. Release truth is terminal and monotonic (M2-B32)

A release attempt that produced `NOT_RELEASED`, `RELEASED`, or
`RELEASE_OUTCOME_UNKNOWN` has answered the question permanently. Every later
call and every durable record repeats that same outcome.

The defect this closes was specific: `SpawnedLauncher.release()` retained only a
`RELEASED` outcome and rebuilt every other answer from `_awaiting_release`,
which the first call had already cleared. A first call reporting
`RELEASE_OUTCOME_UNKNOWN` / `EXECUTION_OUTCOME_UNKNOWN` was therefore followed by
`NOT_RELEASED` / `NO_INSTRUCTION_EXECUTED` — a positive claim that the proposed
command never ran, made by a controller that never held that evidence.

* `cgroup_launch.monotonic_release_truth(previous, candidate)` is the single
  point every caller and every evidence writer goes through. Once a terminal
  outcome exists it is returned unchanged.
* `release_truth_is_downgrade(previous, candidate)` makes the invariant
  testable: after a terminal answer, *any* state change is a downgrade.
* `SpawnedLauncher.observed_release_outcome()` is the public accessor. Before
  any attempt it reports the interim phase `RELEASE_NOT_REQUESTED`, which is
  never recorded as terminal; afterwards it repeats the terminal outcome.
* `abort_gated_effect` reads the launcher's own terminal outcome, so a caller
  that supplies a stronger outcome at cleanup time cannot overwrite it.

No path in this milestone can physically resolve an unknown gate write after the
fact, so no upgrade path exists either. Resolving evidence would require a new
explicit API and new physical proof.

## C2. Every external wait is bounded by this controller (M2-B33)

A timeout implemented by the helper is a promise from the component that is
failing. Each operation that depends on the helper now carries an **absolute
monotonic** deadline this process enforces:

| operation | constant |
| --- | --- |
| helper start-up | `HELPER_STARTUP_DEADLINE_MS` |
| spawn | `HELPER_CONTROL_RPC_DEADLINE_MS` |
| release accept frame | `HELPER_RELEASE_ACCEPT_DEADLINE_MS` |
| release completion frame | `HELPER_RELEASE_COMPLETION_DEADLINE_MS` |
| kill / poll | `HELPER_CONTROL_RPC_DEADLINE_MS` |
| wait | caller timeout + `HELPER_WAIT_RPC_MARGIN_MS` |
| shutdown, including failure cleanup | `HELPER_SHUTDOWN_DEADLINE_MS` |
| launcher exit observation | `LAUNCHER_EXIT_OBSERVATION_DEADLINE_MS` |
| launcher reap | `LAUNCHER_REAP_DEADLINE_MS` |
| helper reap | `HELPER_REAP_DEADLINE_MS` |
| the whole abort path | `ABORT_TOTAL_DEADLINE_MS` |

The deadline is applied by setting and restoring the socket timeout from the
remaining time before **each** underlying syscall, so a sequence of reads cannot
renew its own budget. A nested deadline can never outlive its whole. There is no
`signal.alarm`, `setitimer`, or `SIGALRM` handler anywhere in the package: a
process-wide timer would corrupt unrelated operations.

A deadline that expires mid-frame destroys the length-prefixed framing, so the
connection is marked broken and every later call refuses immediately. A wedged
helper therefore costs one deadline in total rather than one per remaining call.

Classification: expiry before the accept frame and expiry after it are distinct
phases (`RELEASE_ACCEPT_DEADLINE_EXPIRED`,
`RELEASE_COMPLETION_DEADLINE_EXPIRED`) but both are `RELEASE_OUTCOME_UNKNOWN`,
because in either case the helper may already have written the gate.
`NOT_RELEASED` is produced only where the protocol proves non-release: a
terminal first frame, a reported write failure, or a release request that was
never put on the wire at all.

After a helper deadline the controller stops asking. It signals the launcher
through its own pidfd, kills and reaps the helper it forked, and reaps the
launcher the kernel reparents to it. The local cgroup kill domain runs first and
never waits on the helper.

## C3. Proved ownership and reap after helper loss (M2-B34)

The helper forks the launcher, so the launcher is the controller's grandchild.
When the helper dies after the gate write, `cgroup.kill` still destroys the
domain and an empty `cgroup.procs` still proves no live member — but neither
says who observed the exit or who reaped it.

**Chosen architecture: `CONTROLLER_CHILD_SUBREAPER_PLUS_PIDFD_OBSERVATION`.**
The controller calls `prctl(PR_SET_CHILD_SUBREAPER, 1)` before forking the
helper. The kernel then reparents the orphaned launcher to the nearest subreaper
ancestor — this controller — so `waitpid` on that exact PID is a reap this
process performed and can name. A pidfd carries exit observation only:
`waitid(P_PIDFD, ...)` on a process that is not the caller's child fails with
`ECHILD`, which is asserted physically rather than assumed.

Lifecycle of the process-wide flag: acquired immediately before the first
trusted helper is forked, reference counted across concurrent effects, read back
after being set, and restored to its previous value when the last helper closes.
An acquisition inherited across `fork()` records another process's PID and is
discarded rather than trusted, because the kernel flag is not inherited.

`waitpid` is only ever called on an owned PID. `is_addressable_pid()` makes
`waitpid(-1)`, `waitpid(0)`, and `kill(-1, ...)` unreachable, so a concurrent
unrelated child of this controller is never consumed.

These lifecycle facts are recorded separately and are never collapsed:

```text
process_domain_kill_requested   launcher_exit_observed   launcher_reaped
launcher_exit_code              launcher_reaper_role     launcher_reaper_pid
launcher_zombie_remains         helper_exit_observed     helper_reaped
helper_exit_code                cgroup_quiescent         effect_cgroup_removed
```

A repeated cleanup reports the first reap with `launcher_reap_code =
ALREADY_REAPED` and performs no second one. Where the reap cannot be proved —
no subreaper, or a deadline reached — that is recorded as an inability to prove
it, never as a reap performed by an unnamed process.

Rejected alternatives, and why, are recorded in
`implementation/M2_FINAL_PROTOCOL_LIFECYCLE_REPAIR_REPORT.json`.

## C4. Tests

`tests/test_admissible_paired_runner_m2_final_protocol_lifecycle.py` covers the
monotonicity invariant, the deadline primitive, a live silent helper, a helper
held by `SIGSTOP`, helper loss before creation, before release, and after the
gate write, the verified kernel semantics, and the delegated physical
qualification of each.

---

# D. Subreaper and global-deadline closure (M2-B37, M2-B38, M2-B39, M2-B40)

Section C established the ownership architecture and the per-operation
deadlines. It did not make the ownership a precondition, did not make the
acquisition failure-atomic, decided a restoration from the write rather than the
readback, and left the abort path's tail spending fresh fixed durations. This
section closes those four.

## D1. Acquisition is a precondition of the fork (M2-B37)

`ChildSubreaperOwnership.acquire()` previously had three failure paths —
`PR_GET_CHILD_SUBREAPER` unreadable, `PR_SET_CHILD_SUBREAPER` refused, and a
readback that disagreed with a write reporting success — and all three
incremented the reference count and returned a state dict.
`PrivateMountHelper.start()` ignored the returned code and forked regardless.
The controller therefore created a trusted helper whose orphaned launcher it had
no established right to reap, while `_subreaper_acquired` was `True` and the
evidence spoke as though ownership had been proved.

The acquisition is now the first thing `start()` does, and it either returns
kernel-confirmed state or raises `ChildSubreaperUnavailable`:

```text
READ_THE_PREVIOUS_FLAG
SET_THE_FLAG
READ_IT_BACK
REFUSE_UNLESS_THE_READBACK_IS_EXACTLY_1
VALIDATE_THE_ACQUISITION_OBJECT_IS_OWNED_BY_THIS_PID
CREATE_THE_SOCKET_PAIR
FORK
```

On any refusal: `fork()` is not called; no helper or launcher process is
created; no pidfd is created or retained; no success or started event is
produced; the caller receives the classified
`private_mountns_subreaper_unavailable`; the previous process-wide value is
rewritten and the rewrite is observed; and no ownership reference is retained.

Refusal codes: `UNAVAILABLE_ON_THIS_KERNEL`, `SET_FAILED`, `READBACK_FAILED`,
`READBACK_MISMATCH`.

The controller's only fork is `private_workspace._fork()`, so "acquisition
failure never reaches `fork()`" is a property of one named call site rather than
an ordering that has to be inferred. The helper's own fork of the launcher runs
*inside* the helper process, which holds no acquisition — the flag is not
inherited — and is not the trusted controller.

This is fail-closed by design: a kernel or policy that refuses
`PR_SET_CHILD_SUBREAPER` now refuses the whole effect rather than proceeding
without proved ownership. The behaviour change is disclosed in the closure
report's known limitations.

## D2. The acquisition is failure-atomic around the fork (M2-B38)

The acquisition must be taken before the fork, because the flag must be set
before the child exists. Everything between it and the successful ownership
transfer is therefore rollback territory. `socketpair()` now runs *after* the
acquisition so a descriptor failure can be rolled back at all, and the fork is
inside the guarded region.

`_roll_back_failed_start()` runs on every failing exit path, in this order:

```text
DESTROY_AND_REAP_THE_CHILD
CLOSE_EVERY_DESCRIPTOR
RELEASE_THE_ACQUISITION_ONCE
```

The order is not incidental: releasing the acquisition while an orphan of this
controller is still alive would restore the very flag that gives this process
the right to reap it.

The release goes through a `SubreaperReference` handle that releases at most
once, so a repeated rollback reports the first release rather than decrementing
an acquisition a concurrent effect still needs. A failed launch under a
concurrent acquisition yields `REFERENCE_RETAINED`, the flag stays set, and the
surviving effect keeps the ownership it still requires.

Covered failures: `socketpair()` EMFILE, `fork()` EAGAIN, `fork()` ENOMEM, the
parent-side uid/gid map write failing after a real fork, the READY handshake
timing out, and any other exception raised before ownership transfers.

## D3. A restoration is a readback (M2-B39)

`release()` performed the readback and then discarded it, deciding `RESTORED`
from the *write's* error code. A kernel that accepted
`PR_SET_CHILD_SUBREAPER(0)` and still reported `1` therefore produced
`RESTORED`, and a later consumer would act on a flag that was still set.

The release state machine is now:

| observation | result |
| --- | --- |
| an outer acquisition still holds it | `REFERENCE_RETAINED` |
| the write failed | `RESTORE_SET_FAILED` |
| the readback failed | `RESTORE_READBACK_FAILED` |
| the readback disagrees with the intended value | `RESTORE_MISMATCH` |
| the readback equals the intended value | `RESTORED` |
| nothing is held | `ALREADY_RELEASED` |
| the handle was carried across `fork()` | `INHERITED_ACQUISITION_DISCARDED` |

The write's return value alone can never produce `RESTORED`.

A failed restoration keeps `restore_intended`, `restore_observed`,
`restoration_verified=false`, `cleanup_complete=false`, and `previous_value`, so
the last evidence of what this process still owes is not silently decremented
away. A repeated release performs nothing and returns the original terminal
result with `released_nothing=true`; it never overwrites a `RESTORE_MISMATCH`
with `ALREADY_RELEASED`.

A handle or acquisition carried across `fork()` is discarded and the child
writes nothing: it must never restore a process-wide value it never set. That
the flag is not inherited is asserted by forking and reading it in the child,
not assumed.

## D4. One deadline for one bounded cleanup (M2-B40)

`abort_gated_effect()` declared a 30-second total and then let its tail start
fresh fixed durations: `wait_quiescent()` received a new 5.0 seconds computed
from its own clock at call time, `_legacy_terminate_and_reap()` called
`wait(timeout=CAPSULE_TEARDOWN_TIMEOUT_SECONDS)`, and `PrivateMountHelper.close()`
spent a full `HELPER_SHUTDOWN_DEADLINE_MS` and then a *second*, fresh
`HELPER_REAP_DEADLINE_MS`. The stated bound was the total plus whatever the tail
asked for.

`CleanupBudget` is created once at abort entry and is the only source of time
inside it. Stages take capped views:

| stage | grant |
| --- | --- |
| `release_state` | non-blocking |
| `process_domain_kill` | non-blocking |
| `launcher_terminate_and_reap` | a capped `Deadline`; its own sub-steps cap again |
| `descriptor_closure` | non-blocking |
| `cgroup_quiescence` | remaining seconds, capped at `ABORT_QUIESCENCE_TIMEOUT_SECONDS` |
| `cgroup_removal` | non-blocking |
| `subreaper_release` | a capped `Deadline`; `prctl` does not block |

The helper RPC bypass, the pidfd exit observation, and the launcher and helper
reaps are sub-steps of `launcher_terminate_and_reap` and are capped by the same
instant it receives.

Once the budget is spent, `grant_seconds` returns exactly `0.0` and `grant`
returns an expired deadline. Every primitive treats that as one non-blocking
observation: `wait_quiescent(0.0)` performs a single membership read,
`reap_owned_child` a single `WNOHANG` `waitpid`, `observe_process_exit` a single
`poll(0)`, and the legacy wait is skipped entirely. Quiescence, reap, removal,
and restoration are never claimed without observation.

`PrivateMountHelper.close()` accepts a caller deadline and creates at most one
of its own. The cooperative steps — the shutdown exchange and the wait for a
voluntary exit — share a bounded prefix (`HELPER_COOPERATIVE_EXIT_DEADLINE_MS`)
of that one instant, and the forced kill-and-reap takes what is left, so the
cooperative steps cannot spend the guarantee.

The durable cleanup evidence records the ledger: `configured_total_ms`,
`default_total_ms`, `caller_supplied_deadline`, `remaining_at_entry_ms`,
`elapsed_ms`, `remaining_ms`, `deadline_exhausted`, `renewed_after_a_step`, the
per-stage grants, and the completed and incomplete steps. Every recorded
duration is an integer number of milliseconds, because the durable encoding
forbids floating-point values.

`configured_total_ms` is the *input* the caller chose, carried on the
`Deadline` itself as `configured_ms` rather than re-derived from the time that
happens to remain. Re-deriving it is wrong by construction: some of the total is
always already spent by the time anything reads it, so a 30 000 ms deadline
reports 29 999 ms remaining and would misdescribe the very bound the caller
configured. How much of that total was already gone at entry is recorded
separately as `remaining_at_entry_ms`, so neither fact is inferred from the
other. A capped view keeps the cap its step asked for; what the step was
actually granted is the ledger's `granted_ms`.

The subreaper release is part of the cleanup: when the abort path takes the
helper over, kills it and reaps it, that helper will never run its own shutdown,
so the acquisition it holds would outlive every process that justified it.
Nothing is released while the helper is alive — it still owns its acquisition
and its own shutdown ends it.

## D5. Tests

`tests/test_admissible_paired_runner_m2_subreaper_deadline_closure.py` covers the
acquisition gate against injected `prctl` failures with the fork primitive
proved unreached, rollback for `EAGAIN`, `ENOMEM`, `EMFILE` and a real
post-fork parent failure, the restoration state machine including the exact
requested-0/observed-1 reproduction, a real `prctl` cycle verified before and
after, a real forked child proving non-inheritance, the quiescence duration
captured at the boundary it crosses, and the delegated physical qualification of
each.

## D6. What the first delegated qualification found

The first delegated run of all 303 tests executed with zero skips and failed
two of them. Both are recorded here because a closure that hides its own failed
qualification is the defect this milestone keeps closing. Both were closed and
the modified worktree was then re-qualified from scratch:

```text
Ran 309 tests in 106.293s

OK
```

with zero skips, zero failures, and zero errors under `Delegate=yes`,
`TasksMax=infinity`, `ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1`.

**`configured_total_ms` was 29 999, not 30 000.** The budget re-derived the
configured total from the deadline's remaining time, so any elapsed nanosecond
between constructing the deadline and opening the budget cost a millisecond.
Closed by carrying the configured duration on the `Deadline` (`configured_ms`)
and recording `remaining_at_entry_ms` separately.

**A nominal delegated effect returned a `FAILED` receipt.** The cause is not in
the four repaired paths. `cgroup_delegation()` caches a topology contradiction
permanently and never re-bootstraps it — the accepted M2-B29 behaviour — and
`process_supervision._DELEGATION_CACHE` and `resource_limits._TOPOLOGY` are
module-level. The lifecycle module's injected-membership-failure test therefore
left every later effect in the same interpreter running with `available=False`;
on a host whose readiness promised `CGROUP_V2_AND_RLIMIT` that turns the next
*nominal* effect into a `cgroup_membership_unverified` refusal before exec.

It surfaced only now because this closure added a fourth module with a nominal
delegated effect *after* the injecting test; the lifecycle module's own nominal
test runs before it and was unaffected.

The production behaviour is correct and is not weakened. The leak is closed in
the tests: `guard_process_wide_cgroup_caches` restores both module-level caches
after any test that can inject a contradiction, and the nominal delegated tests
assert a live delegation as an explicit precondition so "this controller has no
usable topology right now" can never again be reported as "the nominal effect
path is broken". Every delegated receipt assertion now renders the receipt
classification and its causal evidence, so no physical failure is opaque again.

---

# E. Ownership debt and reap closure (M2-B41, M2-B42, M2-B43)

Section D established that acquisition is a precondition of the fork, that it
is failure-atomic around it, and that a restoration is a readback.  It left
three statements the code could still make untruthfully.

## E1. A nested acquisition is an acquisition (M2-B41)

`ChildSubreaperOwnership.acquire()` had a cached branch: with a positive depth
and `_applied` set it incremented the reference count and returned, without
asking the kernel anything.  `_applied` is a memory of a syscall made at some
earlier instant; the question a second acquisition asks is whether *this
process, right now* is a child subreaper, because that is what authorizes the
fork that follows it.

Every acquisition that can authorize a fork therefore reads
`PR_GET_CHILD_SUBREAPER` immediately before the depth is incremented:

1. read the flag;
2. require exactly `1`;
3. require the acquisition being nested to belong to this PID;
4. require that no unresolved restoration debt stands;
5. only then increment the depth.

A readback that fails, or that returns anything other than `1`, is a refusal.
The refusal changes nothing: the depth, the outstanding references and the
original baseline are exactly as they were, no fork happens, and the classified
`ChildSubreaperUnavailable` carries the expected and the observed value.  The
ownership object is poisoned, so a repeated contradictory acquisition stays
refused, and `active` stops reporting a process that the kernel says is no
longer a child subreaper.

## E2. A failed restoration is a debt (M2-B42)

After a final release failed its restoration verification, the object was left
at depth zero with `_applied` false and nothing owed on paper.  The next
`acquire()` read the *residual* kernel value as a fresh baseline, overwrote the
original one, and a later release could report `RESTORED` to a value this
process never found.

A failed restoration now latches explicit process-wide ownership debt.  It is
created by `RESTORE_SET_FAILED`, `RESTORE_READBACK_FAILED` and
`RESTORE_MISMATCH` on a final release, by a refused acquisition whose rewrite of
the previous value its own readback contradicts, and by a nested acquisition the
live kernel contradicted.  While it stands:

* every acquisition refuses with `RESTORATION_DEBT_OUTSTANDING`;
* no helper is forked;
* the original baseline is immutable — a later failure updates what was last
  intended and last observed, never what is owed;
* `state()`, `acquire()`, `release()` and replacing the ownership object all
  leave it exactly where they found it.

It is stored beside the flag it describes rather than inside the object that
incurred it, because the debt is a fact about this process's flag: replacing the
ownership object, including the module-level singleton, must not be a way to
forget it.  It records the PID that incurred it, so a `fork` child — which
inherits this module's memory but not the flag — neither owes it nor can settle
it.

`settle_restoration_debt()` is the only operation that can clear it.  It writes
the owed baseline, reads it back, and clears the latch only on an exact match;
anything else leaves the debt standing with its attempt count incremented.  It
refuses while any reference is outstanding, because restoring the baseline under
a live helper would take back the very right to reap that helper's orphans.

The ownership state machine is stated rather than implied:
`CLEAN_UNOWNED`, `ACTIVELY_OWNED`, `NESTED_REFERENCE_RETAINED`,
`RESTORATION_OWED`, `POISONED_UNREADABLE`, `TERMINAL_RESTORED`,
`INHERITED_DISCARDED`.

## E3. Reap before release, and retry what did not finish (M2-B43)

`PrivateMountHelper.close()` set one flag on entry and used it for two
questions.  A helper that could not be reaped inside the deadline had its
subreaper ownership released anyway — the very flag that grants the right to
reap it — reported the restoration complete, and could never be retried, because
the second call returned immediately.  A real helper could therefore remain an
unreaped zombie while the controller's depth was zero and the flag was restored.

Protocol closure and lifecycle completion are now separate states:

| state | meaning |
| --- | --- |
| `PROTOCOL_OPEN` | the framed protocol may still be spoken |
| `PROTOCOL_CLOSED_HELPER_ALIVE` | the socket is shut; the helper is a live child |
| `PROTOCOL_CLOSED_EXIT_OBSERVED` | the exit was observed; nobody has reaped it |
| `REAPED_OWNERSHIP_RETAINED` | reaped; the acquisition has not ended yet |
| `CLEANUP_COMPLETE` | reaped, released, and nothing owed |

The ordering is: observe or force the exit, reap the exact PID, then release the
acquisition exactly once.  Ownership is released only after a positive reap, at
every site that can release it — `close()`, `release_subreaper_if_reaped()`, and
the failed-start retry.  `close()` is idempotent once the cleanup is complete
and retries the reap on every later call while it is not; a later call with a
live budget forces the exit, reaps that exact PID, releases the exact reference,
and returns a terminal result.  `waitpid` is still only ever called on a single
owned PID, so a concurrent unrelated child of this controller is never consumed.

The same rule governs the failed-start rollback.  A child this controller forked
and could not reap keeps its acquisition, is recorded as an incomplete cleanup,
and leaves a retryable entry behind, so the reap and the single release stay
reachable rather than being traded for a released flag.
`PrivateExecutionView.close()`, `BoundRuntime.close()` and
`_EffectPreparation.close()` return and propagate that evidence, and the effect
preparation keeps its view while the cleanup is incomplete so the retry has a
handle to use.

## E4. Tests

`tests/test_admissible_paired_runner_m2_ownership_debt_reap_closure.py` covers
the nested revalidation against a really cleared flag and an injected readback
failure with the fork primitive proved unreached, the debt latch across all
three failed-restoration results plus object replacement and a real `fork`
child, settlement in both directions, the expired-deadline close that leaves a
real helper unreaped with its ownership retained, the retry that reaps that
exact PID and releases exactly once, a real zombie reaped before the release, a
concurrent unrelated child left alone, the failed-start rollback ordering, the
caller propagation, and the semantic coherence of the current validation
artifacts.
