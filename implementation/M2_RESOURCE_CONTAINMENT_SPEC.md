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

---

# Addendum: cgroup topology qualification (M2-B25)

Branch: `paired-runner/m2-b25-cgroup-topology-repair`
Starting commit: `f2e766fe1ed1c3ac60f4cf542a6e5e7723e72b77`

## A1. What section 6 above described, and what changed

Section 6 recorded that on the qualification host no subtree is delegated and
the mechanism in force is `RLIMIT`. That remains true of an undelegated host and
is still reported honestly. What was *not* true is the implication that a
delegated host would therefore have worked: on a host that genuinely delegates a
writable subtree, the old readiness probe reported `available=true` after a bare
`mkdir`/`rmdir`, and the first real per-effect limit write then failed with
`EACCES`, because the delegated parent still held the controller and cgroup v2
refuses to distribute controllers out of a populated cgroup.

Readiness now performs the whole rehearsal — manager-leaf bootstrap, controller
activation, a real probe effect with `pids.max` and `memory.max` written and read
back — so `CGROUP_V2_AND_RLIMIT` is only ever promised by a host that has already
delivered it. See `M2_CGROUP_LAUNCH_PRIMITIVE_SPEC.md`, addendum A2–A7, for the
topology, the bootstrap sequence, the classified outcomes, and the lifecycle.

## A2. Aggregate layer, restated

When the topology is initialized, each effect runs in a sibling cgroup of the
trusted manager leaf carrying:

| Control file | Value | Source |
| --- | --- | --- |
| `pids.max` | `ResourceBounds.max_processes` (64) | written, then read back and compared exactly |
| `memory.max` | `ResourceBounds.max_address_space_bytes` (2 GiB) | written, then read back and compared exactly |

`max` is never accepted where a finite bound was required. The values recorded in
the durable `resource-observation` (`cgroup.pids.max=`, `cgroup.memory.max=`,
`cgroup.effect_path=`, `cgroup.membership_verified=`) are the values the kernel
returned, not the values the controller intended. Descendants inherit the effect
cgroup, so the bound is aggregate over the whole process domain rather than
per-process as `RLIMIT` alone would be.

## A3. Physical qualification rule

`CGROUP_V2_AND_RLIMIT` is claimed for an effect only when membership was
verified from a real cgroup2 `cgroup.procs` *before* the trusted gate was
released. An attach or verification failure terminates and reaps the child, the
proposed command executes no instruction, and the effect is refused with
`cgroup_membership_unverified`. There is no silent downgrade to `RLIMIT` after
readiness has promised the cgroup layer.

## A4. Test matrix addendum

`tests/test_admissible_paired_runner_m2_b25_cgroup_topology.py`

| Requirement | Test |
| --- | --- |
| the old false-positive probe shape is refused | `FalsePositiveProbeRegressionTests` |
| every bootstrap transition is classified and rolls back | `ManagerLeafBootstrapTests` |
| one topology per process, PID-bound, no nested leaves | `TopologyIdempotenceTests` |
| complete writes, explicit newlines, exact readback | `KernelWriteTests` |
| creation alone is never success | `EffectCgroupTests` |
| a filesystem fixture is never kernel evidence | `EvidenceRuleTests` |
| lifecycle is stated, not implied | `LifecycleTests` |
| real bootstrap and effect limits | `test_real_delegated_cgroup_bootstrap_and_effect_limits` |
| membership before gate release, production path | `test_production_command_is_member_before_gate_release` |
| a refused proof executes no command | `test_failed_membership_verification_executes_no_command` |
| descendants inherit the effect cgroup | `test_descendant_inherits_effect_cgroup` |
| repeated effects reuse one manager topology | `test_repeated_production_effects_reuse_one_manager_topology` |

Under `ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1` the delegated tests fail rather
than skip. A skipped delegated test is a closure failure, never a green run.

# Addendum B: final fail-closed containment rules (M2-B28, M2-B29, M2-B30)

Normative.

## B1. Readiness may not outlive its evidence

`CgroupDelegation.available` is a statement about a completed physical
rehearsal **including its cleanup**. `probe_cleanup` records the probe path,
members observed before removal, whether `rmdir` was attempted, its exact errno,
whether removal succeeded, whether absence was verified, and whether a residual
path exists. `available=true` with a residual probe cgroup is unreachable, and a
probe over its own residue collides (`EFFECT_COLLISION`) rather than
false-greening.

## B2. A cached answer is revalidated before every effect

`process_supervision.cgroup_delegation()` never returns a cached available
result without re-deriving the topology from the kernel first (see
M2_CGROUP_LAUNCH_PRIMITIVE_SPEC.md §B2). A contradiction yields
`STALE_CACHED_TOPOLOGY`, and `effective_mechanism` then reports `NONE` when
readiness had promised `CGROUP_V2_AND_RLIMIT`, so the effect refuses rather than
degrading.

## B3. Aggregate containment doubles as the kill domain

Because every process of the effect is accounted to one per-effect cgroup, that
cgroup is the termination boundary used by the abort path. It reaches every
descendant, including one that changed session or double-forked, and it reaches
nothing outside itself.

## B4. Test matrix addendum

| Case | Test |
| --- | --- |
| probe removed, absence verified | `test_a_successful_probe_removes_the_probe_and_verifies_its_absence` |
| `rmdir` EBUSY / EACCES | `test_an_ebusy_rmdir_refuses_and_never_says_removed`, `test_an_eacces_rmdir_refuses_with_its_exact_errno` |
| success with residual path | `test_a_success_that_leaves_the_path_behind_is_refused` |
| unexpected disappearance | `test_an_unexpected_disappearance_is_classified_not_called_success` |
| occupied probe | `test_an_occupied_probe_is_never_removed_and_never_reported_removed` |
| cleanup precedes any positive result | `test_no_positive_result_is_constructed_before_cleanup_completes` |
| repeat after cleanup failure | `test_a_repeated_probe_after_a_cleanup_failure_cannot_false_green` |
| controller disabled / unreadable / missing | `StaleCachedTopologyTests` |
| same basename, different full path | `test_the_same_basename_at_a_different_full_path_is_refused` |
| replaced parent / leaf, nested leaf | `test_a_replaced_effect_parent_inode_is_refused`, `test_a_replaced_manager_leaf_is_refused`, `test_a_nested_manager_leaf_is_refused` |
| parent regained a process | `test_a_parent_that_gained_an_unrelated_process_is_refused` |
| supervisor cache revalidates / refuses | `SupervisorDelegationCacheTests` |
| release states and phases | `ReleaseStateClassificationTests`, `ReleaseProtocolTests` |
| bounded, idempotent, leak-free abort | `AbortGatedEffectTests` |
| delegated physical qualification | `DelegatedFinalFailClosedTests` |

---

# C. Typed cgroup membership reads (M2-B35)

## C1. An unreadable membership is not an empty one

`_members_of()` mapped an unreadable `cgroup.procs` to `set()`. That made two
opposite facts identical:

```text
"the kernel says this cgroup is empty"
"this controller could not read this cgroup at all"
```

Every security-relevant decision downstream is a decision about emptiness, and
each of them accepted a failed read as a positive answer.

`read_cgroup_members(path) -> CgroupMembership` replaces it. The typed result
carries:

| field | meaning |
| --- | --- |
| `path` | the exact cgroup directory read |
| `read_ok` | whether `cgroup.procs` could be read at all |
| `error_code` | the errno name when it could not |
| `pids` | the member PIDs this namespace can name |
| `malformed` / `malformed_detail` | content that is not a list of decimal PIDs |
| `opaque_member_count` | members this PID namespace cannot name |
| `usable` | `read_ok and not malformed` — may this observation decide anything |
| `observed_empty` | the kernel positively reported no members of any kind |
| `fully_addressable` | every member can be named, and therefore signalled |

`EffectCgroup.members()` raises `CgroupMembershipUnreadable` rather than
returning an empty set, so no caller can receive a bare empty set on a failed
read.

## C2. Members this PID namespace cannot name

The kernel renders `cgroup.procs` in the *reader's* PID namespace and prints `0`
for a member that namespace cannot name. Physical inspection of the development
host's root cgroup found 207 such entries. A `0` is neither a PID nor noise: it
is a live member this controller may not address. Folding it into `pids` would
invent a process; discarding it would report a populated cgroup as empty. It is
counted separately, it defeats `observed_empty`, and it is never signalled
individually.

## C3. Every security-relevant caller fails closed

| caller | behaviour on an unreadable or malformed read |
| --- | --- |
| `_topology_is_still_true` manager membership | refuse the cached topology |
| `_topology_is_still_true` parent depopulation | refuse (`parent/cgroup.procs -> EACCES`) |
| `_bootstrap_topology` controller-move verification | roll back, `CGROUP_MEMBERSHIP_UNREADABLE` |
| `_bootstrap_topology` parent depopulation | roll back; readiness is never positive without observed emptiness |
| `_bootstrap_topology` rollback | an owned leaf is removed only when observed empty |
| `_reuse_manager_leaf` parent depopulation | refuse |
| `_remove_owned_probe` | `PROBE_MEMBERSHIP_UNREADABLE`; `rmdir` is not attempted |
| `attach_and_verify` pre-attach emptiness | refuse before any gate release |
| `attach_and_verify` post-attach membership | refuse; membership is not verified |
| `kill_domain` | `cgroup.kill` still runs; no member is signalled individually and none is claimed |
| `wait_quiescent` | not quiescent, with the exact refusal recorded |
| `close` | not removed, not called removed, cgroup left in place |
| `_containment_evidence` | records `cgroup.membership_read_refused=…`, never an empty list |

New classified codes: `CGROUP_MEMBERSHIP_UNREADABLE`,
`CGROUP_MEMBERSHIP_MALFORMED`, `PROBE_MEMBERSHIP_UNREADABLE`.

## C4. Test matrix addendum

| Case | Test |
| --- | --- |
| readable empty vs unreadable vs malformed | `TypedMembershipReadTests` |
| a member this namespace cannot name | `test_a_member_this_namespace_cannot_name_still_populates_the_cgroup` |
| `parent/cgroup.procs -> EACCES` revalidation | `test_cache_revalidation_refuses_an_eacces_parent` |
| unreadable manager leaf, malformed parent | `test_cache_revalidation_refuses_an_unreadable_manager_leaf`, `test_cache_revalidation_refuses_a_malformed_parent` |
| bootstrap parent depopulation and move verification | `test_bootstrap_parent_depopulation_refuses_an_unreadable_parent`, `test_bootstrap_manager_verification_refuses_an_unreadable_leaf` |
| probe emptiness and readiness | `test_probe_cleanup_refuses_to_remove_an_unreadable_probe`, `test_no_positive_readiness_is_built_over_an_unreadable_probe` |
| pre-attach and post-attach | `test_pre_attach_emptiness_refuses_an_unreadable_effect_cgroup`, `test_pre_attach_refuses_a_cgroup_that_is_not_observed_empty`, `test_post_attach_verification_refuses_an_unreadable_read` |
| kill domain, quiescence, removal | `test_the_kill_domain_signals_nothing_it_could_not_observe`, `test_quiescence_is_never_claimed_over_an_unreadable_membership`, `test_removal_is_refused_over_an_unreadable_membership` |
| no bare empty set on a failed read | `test_no_caller_can_receive_a_bare_empty_set_on_a_failed_read` |
| delegated physical qualification | `test_an_unreadable_membership_refuses_release_quiescence_and_removal` |

---

# D. Bounded cleanup budget (M2-B40)

Section B3 made the aggregate cgroup layer double as the kill domain, and the
abort path destroys that domain, waits for quiescence, and removes the cgroup.
Those three steps are part of one bounded operation, and quiescence in
particular is a *wait*.

`EffectCgroup.wait_quiescent(timeout_seconds)` is unchanged: it polls
`cgroup.procs` until it observes an empty membership or the duration it was
given elapses, and it claims quiescence only from a positive observation of an
empty, readable membership. What changed is where that duration comes from.

The abort path previously handed it `ABORT_QUIESCENCE_TIMEOUT_SECONDS` — a fresh
5.0 seconds computed from the wall of the moment, independent of the 30-second
total the abort had already declared and possibly already spent. The stated
bound was therefore the total plus this wait, plus whatever the steps after it
asked for.

The duration is now `budget.grant_seconds("cgroup_quiescence",
ABORT_QUIESCENCE_TIMEOUT_SECONDS)`: the remaining time of the one absolute
deadline created at abort entry, capped at the stage maximum. Once that deadline
is spent the grant is exactly `0.0`, which `wait_quiescent` treats as a single
non-blocking membership read — an observation, not a claim, and never a new
interval.

Removal keeps its own rule. `close()` reads membership and calls `rmdir`;
neither blocks, so removal runs even with nothing left of the budget, and it
still reports `removed` only when the absence was verified. A cgroup whose
membership could not be read is still never removed and never called removed.

The per-stage grants, the configured total, the elapsed time, deadline
exhaustion, and the completed and incomplete steps are recorded in the durable
cleanup evidence under `cleanup_budget`. `quiescence_granted_ms` records, in
integer milliseconds, exactly what this stage received.

## D1. Test matrix addendum

| Case | Test |
| --- | --- |
| quiescence receives `0.0` once the whole deadline is exhausted | `test_wait_quiescent_never_receives_a_new_fixed_five_seconds` |
| quiescence receives the remaining duration while time is left | `test_wait_quiescent_receives_the_remaining_duration_when_time_is_left` |
| an exhausted budget blocks on nothing | `test_an_already_expired_deadline_at_entry_blocks_on_nothing` |
| removal after exhaustion still verifies what it claims | `test_the_deadline_expiring_before_removal_still_verifies_what_it_claims` |
| no stage receives more than the budget had left | `test_every_stage_receives_only_the_remaining_time` |
| the whole abort stays inside its configured total | `test_the_total_elapsed_time_stays_inside_the_configured_total` |
| no successful field after unobserved exhaustion | `test_no_successful_field_is_claimed_after_unobserved_exhaustion` |
| repeated bounded cleanup stays idempotent | `test_a_repeated_bounded_cleanup_stays_idempotent` |
| delegated physical qualification | `test_a_wedged_effect_aborts_inside_the_configured_global_bound` |

---

# E. Process-lifecycle completion is not protocol closure (M2-B43)

Section D bounded the whole cleanup with one absolute deadline. A bound that
expires is not a failure of the bound — it is the point at which the cleanup
must say what it did not finish.

The trusted mount-namespace helper is a direct child of this controller and
holds the process-wide subreaper acquisition that was taken before it was
forked. Its shutdown therefore owes three distinct facts, not one:

* the framed protocol is closed;
* the exact helper PID is positively reaped;
* the acquisition that its lifetime justified is released.

These were previously collapsed into a single `_closed` flag set on entry, so a
shutdown whose reap failed still released the acquisition, reported the
restoration complete, and refused to retry. The residual was a live or zombie
child of this controller, no longer reapable through a flag the controller had
just given back.

The lifecycle is now recorded as separate facts — `protocol_open`,
`protocol_closed`, `helper_alive`, `helper_exit_observed`, `helper_reaped`,
`ownership_retained`, `ownership_released`, `cleanup_complete` — and the
containment rule is:

> Subreaper ownership may not be released until every helper process for that
> ownership reference is positively reaped.

An incomplete cleanup is retryable, not terminal. A later call with a live
budget forces the exit, reaps that exact PID, releases the exact reference, and
returns `cleanup_complete`. Once complete, a repeat performs nothing. The
release happens exactly once on either path.

The bounded abort path is unchanged in its ordering and keeps its accepted
behaviour: a helper that is still alive keeps its acquisition, because its own
shutdown will end it, and only a helper this controller has itself killed and
reaped has its acquisition released inside the abort.

## E1. Test matrix addendum

| Case | Test |
| --- | --- |
| an expired deadline leaves the helper unreaped and owned | `test_an_expired_deadline_leaves_the_helper_unreaped_and_owned` |
| cleanup is incomplete while the helper remains | `test_cleanup_is_incomplete_while_the_helper_remains` |
| no release is attempted before the reap | `test_no_release_is_attempted_before_the_reap` |
| a retry with a live budget reaps then releases | `test_a_second_call_with_a_live_budget_reaps_then_releases` |
| the release happens exactly once | `test_the_release_happens_exactly_once` |
| a completed cleanup reaps and releases nothing | `test_a_repeated_call_after_completion_reaps_and_releases_nothing` |
| a zombie helper is reaped before the release | `test_a_zombie_helper_is_positively_reaped_before_the_release` |
| a concurrent unrelated child is never reaped | `test_a_concurrent_unrelated_child_is_never_reaped` |
| the failed-start rollback follows the same ordering | `test_a_rollback_over_an_unreaped_child_retains_the_acquisition` |
| callers propagate incomplete cleanup truthfully | `test_the_private_execution_view_propagates_incomplete_cleanup` |
| delegated physical qualification, expired deadline | `test_an_expired_deadline_leaves_a_real_helper_unreaped_and_owned` |
| delegated physical qualification, retry | `test_a_retry_reaps_the_exact_pid_and_releases_exactly_once` |

---

# F. One process owns one flag, and one cleanup outlives its frame (M2-B45 … M2-B48)

Section E separated protocol closure from lifecycle completion and made an
incomplete cleanup retryable. Four things were still true underneath it.

## F1. Active ownership is process-wide, not object-local

`PR_SET_CHILD_SUBREAPER` is a single flag on a single process. The restoration
*debt* was already process-wide, but the *active* ownership — depth, baseline,
owner PID, applied bit, and the lock serialising them — lived on whichever
`ChildSubreaperOwnership` happened to be constructed. Two objects could
therefore each own the one flag:

* object A acquires: the flag reads 1, A's baseline is the 0 it found;
* object B acquires: B's own depth is 0, so it takes the *fresh* path and reads
  the residual 1 back as **its** baseline;
* A releases: the flag is restored to 0 — while B still reports active
  ownership, depth 1, `code=APPLIED`, and a valid reference.

There is now exactly one `_ActiveOwnership` record and one `_OWNERSHIP_LOCK` per
process, and every ownership object is a handle onto it:

> One process-wide domain owns one original baseline, one refcount, one active
> owner PID, one kernel-readback truth, one restoration state, and one lock. No
> object may restore the flag while any process-wide reference remains, and no
> object may report ownership the kernel contradicts.

A fresh activation — and the discard of one inherited across `fork` — advances a
**generation**. A `SubreaperReference` records the generation it was cut from
and is valid only while that generation is live, the depth is positive, this PID
is the owner, and nothing is owed. Nothing here relies on only one ownership
object being constructed: an import discipline is not an invariant.

## F2. A failed start is complete when it is settled

`_UnsettledFailedStart.cleanup_complete` was `reaped and released`. A retry could
therefore reap the exact child, receive `RESTORE_MISMATCH` from its single
release, report the cleanup complete, and delete the only entry that could still
settle it. Completion now requires four facts:

> the exact child positively reaped; the exact reference released exactly once;
> the restoration positively settled; and no outstanding process-wide debt.

The retry order is fixed — reap, release once, settle — and the entry is removed
only when all four hold.

## F3. A retryable cleanup must be able to progress

After a helper reap and an unsettled release, `close()` reported
`cleanup_retryable=true` for ever: the reference was spent, the reap was done,
and no production caller invoked the process-wide settlement. `close()` now
performs that settlement itself, keeps the single release result immutably
beside every settlement attempt, becomes terminal only on an exact baseline
readback, and names the operation a retry would perform:
`REAP_THE_EXACT_HELPER_PID`, `RELEASE_THE_ACQUISITION_ONCE`,
`SETTLE_THE_PROCESS_WIDE_RESTORATION_DEBT`, `NOTHING_REMAINS`.

## F4. Incomplete cleanup outlives the frame that detected it

Every object could *return* incomplete cleanup evidence and the production call
chain dropped all of it. A PID-bound process registry now retains each
unresolved cleanup under a deterministic id (`cleanup-<pid>-<counter>`), records
the helper PID and the ownership generation, drains boundedly and idempotently,
removes an entry only when its cleanup is terminal, retains no completed object
and no filesystem path, and refuses to start a further trusted helper at its
declared capacity. The evidence travels materialisation refusal →
`PrivateExecutionView.close` → `BoundRuntime.close` → `_run_command` →
`_EffectPreparation.close` → `_execute_permitted_effect` →
`EffectExecutionOutcome`, and:

> a command that ran to completion inside a view whose cleanup did not is
> classified `lifecycle_cleanup_incomplete`, never reported OK.

The command's own facts — started, exit code, output — and the effect-boundary
truth are preserved exactly; only the tool outcome is classified.

## F5. Process ownership settled is not containment settled

The first delegated qualification of this closure failed two tests on one leaked
per-effect cgroup. The diagnosis is the fourth obligation:

`EffectCgroup.close()` already refused, truthfully, to remove a cgroup that
still held members, and kept its path so the removal could be retried. What
nothing kept was the *object*. It was a local of the supervision frame, so the
retry became unreachable the moment that frame returned, and the directory
survived for the life of the controller. The registry retained the helper and
the view — the process-ownership obligations — and lost the containment one.

> A registry entry is removed only when **every** obligation of that effect is
> positively terminal: the exact helper reap, the ownership release and its
> restoration-debt settlement, descriptor closure, cgroup quiescence
> verification, and removal of the exact owned per-effect cgroup. Process
> ownership being settled does not settle a containment domain.

Every retained handle answers one protocol, `settle_cleanup(deadline=...)`, so a
drain discharges a helper, a view and a cgroup the same way and cannot silently
skip a kind it does not recognise. For a cgroup the settlement is ordered:

1. destroy the process domain as a kill domain;
2. verify quiescence by a positively observed empty `cgroup.procs`;
3. reap the exactly owned members, so a kill leaves no zombie holding the
   domain;
4. remove the exact owned directory and verify its absence.

"Exact" is enforced by identity, not by name. The device and inode of the
directory this controller created are recorded at creation and re-checked before
`rmdir`, so a cgroup that was removed and recreated under the same name — a
different cgroup, with different controller state and different members — is
refused rather than destroyed.

## F6. Test matrix addendum

| Case | Test |
| --- | --- |
| two objects share one process-wide depth | `test_two_ownership_objects_share_one_process_wide_depth` |
| a second object creates no second baseline | `test_a_second_object_does_not_create_a_second_baseline` |
| releasing A while B holds keeps the flag set | `test_releasing_one_object_while_another_holds_keeps_the_flag_set` |
| the final release restores the baseline once | `test_the_final_release_restores_the_original_baseline_exactly_once` |
| the audited reproduction is impossible | `test_the_audited_reproduction_cannot_be_produced` |
| a stale reference is invalid | `test_a_reference_from_a_replaced_activation_is_stale` |
| inherited active state is discarded in the child | `test_an_inherited_active_state_is_discarded_safely_in_the_child` |
| concurrent acquisitions cannot split ownership | `test_concurrent_acquisitions_are_serialized_and_cannot_split_ownership` |
| a failed start with an unsettled restoration is retained | `test_a_reap_with_a_restore_mismatch_is_incomplete_and_retained` |
| the next retry settles and removes the entry | `test_the_next_retry_settles_the_debt_and_removes_the_entry` |
| the release happens exactly once across retries | `test_the_release_happens_exactly_once_across_every_retry` |
| a helper close that mismatches is not terminal | `test_a_close_whose_restoration_mismatches_is_not_terminal` |
| a later close settles the debt | `test_a_retry_after_a_mismatch_settles_the_debt` |
| a failed settlement never claims completion | `test_a_failed_settlement_never_claims_completion` |
| only incomplete cleanups are registered | `test_only_an_incomplete_cleanup_is_registered` |
| the handle survives its wrapper | `test_the_registry_retains_the_handle_after_the_wrapper_is_destroyed` |
| a forked child trusts no parent handle | `test_a_forked_child_trusts_no_parent_registry_handle` |
| capacity refuses a new effect fail-closed | `test_registry_capacity_refuses_a_new_effect_fail_closed` |
| the preparation returns its cleanup evidence | `test_the_preparation_close_returns_its_cleanup_evidence` |
| `_run_command` propagates incomplete cleanup | `test_run_command_propagates_incomplete_cleanup_evidence` |
| a completion cannot hide an unresolved cleanup | `test_a_completed_command_with_an_unresolved_cleanup_is_not_green` |
| delegated physical qualification, two real owners | `test_two_real_owners_share_one_real_process_wide_flag` |
| delegated physical qualification, real settlement | `test_a_real_helper_settles_its_restoration_on_a_later_close` |
| delegated physical qualification, surviving cleanup | `test_an_incomplete_cleanup_survives_the_wrappers_that_detected_it` |
| an unremovable cgroup is retained and registered | `test_an_unremovable_cgroup_is_retained_and_registered` |
| a later bounded drain removes that exact cgroup | `test_a_later_bounded_drain_removes_that_exact_cgroup` |
| the entry remains while removal fails | `test_the_entry_remains_while_removal_fails` |
| the entry remains while membership is unreadable | `test_the_entry_remains_while_membership_is_unreadable` |
| removal targets the owned identity only | `test_removal_is_attempted_only_for_the_exactly_owned_cgroup` |
| no unrelated cgroup is removed | `test_no_unrelated_cgroup_is_removed_by_a_drain` |
| kill, quiescence and removal are three observations | `test_the_settlement_evidence_states_each_step_separately` |
| a removed cgroup is never registered | `test_a_removed_cgroup_is_never_registered` |
| delegated physical qualification, real leaked domain | `test_a_real_unremovable_cgroup_is_retained_and_later_drained` |

---

# G. Exact identity, separate reap, bounded retention (M2-B50 … M2-B54)

Five closures, each of which removes a way for this substrate to say something
that is not so.

## G1. Ownership is a descriptor, not a name (M2-B50)

`stat(path)` followed by `write(path/"cgroup.kill")` resolves one name twice,
and anything may happen in between.  The identity comparison that used to guard
only the final `rmdir` therefore protected nothing that mattered: by the time it
ran, a same-named replacement had already been enumerated, had already received
`cgroup.kill`, had already had its members signalled individually, and had
already been waited on for quiescence.

An `EffectCgroup` now retains a *capability*:

* a directory descriptor opened on the created cgroup with `O_DIRECTORY` and
  `O_NOFOLLOW`, so a name that has become a symlink or a regular file fails at
  the open rather than after a write has reached it;
* the `st_dev:st_ino` observed **through** that descriptor;
* a descriptor for the delegated parent, which is what proves the owned name
  still resolves to the owned object;
* the leaf name, and an explicit released state.

Every one of these is descriptor-relative: the `cgroup.procs` read, the
`cgroup.procs` write that attaches, the `pids.max` and `memory.max` writes and
readbacks, the `cgroup.kill` presence probe, the `cgroup.kill` write, the
quiescence membership reads, and the removal-eligibility read.

`verify_owned_identity()` runs before the attach, before `kill_domain`, again
between the enumeration and the per-member signals, before `close`'s membership
read, and again immediately before the `rmdir`.  It answers three questions
separately and never collapses them: is the retained descriptor still the
directory it was opened on, does the owned name still resolve to that exact
object, and — when it does not — is the object itself gone or has it merely been
displaced by something this controller may not touch.

| code | meaning |
| --- | --- |
| `EXACT_OWNED_CGROUP` | proved; the action may proceed |
| `NO_RETAINED_DIRECTORY_DESCRIPTOR` | exactness cannot be proved at all |
| `RETAINED_DESCRIPTOR_IDENTITY_CHANGED` | the descriptor is not what it was |
| `PATHNAME_NAMES_A_DIFFERENT_OBJECT` | a replacement holds the name |
| `PATHNAME_IS_NOT_A_DIRECTORY` | a symlink or a file holds the name |
| `PATHNAME_ABSENT` | the name is gone; the descriptor decides the rest |
| `PARENT_DIRECTORY_UNREADABLE` | nothing is proved, so nothing is done |

Disappearance is a positive observation, not an absence of evidence.  The
obligation is discharged only when the descriptor proves the created object is
gone — `ENODEV` or `ESTALE` from an interface-file open through it, or an
interface file that is no longer there together with a name that no longer
resolves to the owned inode.  A same-named replacement is never adopted, never
read, never signalled and never removed.

Linux offers no `rmdir` by descriptor.  The removal is therefore a
verify-then-act-then-prove sequence: the owned identity is proved immediately
before the `rmdir`, and afterwards the retained descriptor is asked whether the
owned object is the object that went away.  The post-condition is recorded
rather than assumed.

## G2. Containment cleanup and process cleanup are two obligations (M2-B51)

A removed cgroup proves the containment domain is gone.  It proves nothing about
whether the processes this controller owned inside it were reaped: `cgroup.kill`
leaves zombies, a zombie belongs to no cgroup, a settlement that took one
non-blocking `waitpid` over a snapshot taken *before* the kill misses anything
that joined afterwards, and `ECHILD` means "not this controller's child" — which
is equally true of a process somebody else reaped and of one nobody did.

Exact process obligations are therefore retained per PID, independently of
membership:

| state | meaning |
| --- | --- |
| `PENDING` | not yet positively accounted for |
| `REAPED_BY_THIS_CONTROLLER` | `waitpid` on this exact PID returned it |
| `REAPED_BY_A_NAMED_TRUSTED_COMPONENT` | durable evidence names the reaper |
| `UNRESOLVED` | `waitpid` refused and no reaper can be named |

Only the middle two are terminal.  `cleanup_complete` is
`containment_settled AND process_obligations_complete`, and the two facts are
separate fields in the cleanup document and in the registry entry.

Ownership is never inferred from arbitrary membership.  A member is adopted as
an obligation only when it is proved to be this controller's direct child from
`/proc/<pid>/status`; every other member is killed by the domain and never
waited on, because a `waitpid` on a PID this process does not own is at best an
`ECHILD` and at worst a wait on an unrelated child a PID reuse handed over.  The
production supervision path records the launcher as an owned process before the
attach and names its reaper — the trusted controller or the mount-namespace
helper — after the wait, on both the nominal and the abort path.

## G3. Capacity is reserved before the obligation exists (M2-B52)

`require_capacity()` checked and returned; `record()` then allocated an id and
inserted unconditionally, with a whole effect in between and no lock anywhere.
The check could pass at 63, the effect could run, and the insertion could take
the registry past its bound — or two threads could each pass the check and each
insert.

Capacity is now *reserved*: one unit taken atomically against retained entries
plus outstanding reservations, before `PrivateMountHelper.start` forks and
before `EffectCgroup.create` calls `mkdir`.  The token is carried through and is
either converted into exactly one entry or given back.  An insertion with no
reservation must still fit inside the capacity in its own right.  A saturated
process creates no directory and forks no helper.

A registrar exception is no longer swallowed.  It becomes a typed
`CLEANUP_REGISTRATION_FAILED` lifecycle failure, the cleanup is not called
complete over it, and the handle is retained in a PID-bound process-level list
that `drain_incomplete_cleanups` also drains — because an obligation nothing can
name is exactly the leak the registry exists to prevent.

## G4. Linear release and serialised cleanup (M2-B53)

Every reference and cleanup handle is a linear capability.  `SubreaperReference`
holds a lock covering the released check, the owner release and the publication
of the terminal document, and the owner release happens *before* the handle is
marked spent, so a release that could not complete leaves the capability
unspent.  `PrivateMountHelper`, `_UnsettledFailedStart` and `EffectCgroup` each
hold a re-entrant lifecycle lock over their reap, release, settlement and
removal.

The registry never holds its global lock across a blocking cleanup: a drain
claims an entry under the lock, settles it under the handle's lock outside the
lock, and reacquires the lock to publish or remove — and only if the entry it
claimed is still the entry registered.  Entries carry a monotonic registry
generation, so a stale claim cannot remove a newer entry.

## G5. One deadline for one whole drain (M2-B54)

A drain with no caller deadline used to create a fresh helper-shutdown deadline
*inside* the loop, so at capacity a "bounded" drain could spend sixty-four
complete budgets.  One `CleanupBudget` is now opened before the iteration and
every claimed entry receives a capped view of what is left of it.  Once the
budget is spent the remaining entries receive one non-blocking evidence read,
are reported with `attempted=false`, and are retained.  A repeated drain is a new
caller-owned operation and may be given a new explicit deadline.  The ledger —
configured total, elapsed, remaining, exhaustion and per-entry grants, all
integers — is published as `cleanup_registry_evidence().last_drain`.

## G6. Test matrix addendum

| property | test |
| --- | --- |
| creation binds a descriptor and its identity | `test_creation_binds_a_directory_descriptor_and_its_identity` |
| a populated replacement receives no `cgroup.kill` | `test_a_populated_replacement_receives_no_cgroup_kill` |
| a populated replacement receives no per-member signal | `test_a_populated_replacement_receives_no_per_member_signal` |
| a symlink replacement is refused before any I/O | `test_a_symlink_replacement_is_refused_before_any_read_or_write` |
| a swap after the check cannot redirect the action | `test_a_swap_between_the_check_and_the_action_cannot_redirect_it` |
| reads still address the original object | `test_membership_reads_still_address_the_original_object` |
| removal targets only the exact owned object | `test_final_removal_targets_only_the_exact_owned_object` |
| external disappearance discharges, adopts nothing | `test_external_disappearance_discharges_without_adopting_a_replacement` |
| an unreadable parent refuses | `test_an_unreadable_parent_refuses_rather_than_claiming_exactness` |
| an attach into a replacement is refused | `test_an_attach_into_a_replacement_is_refused` |
| the capability is released only when nothing remains | `test_the_capability_is_released_only_once_nothing_remains` |
| `waitpid == 0` retains and reports incomplete | `test_waitpid_zero_retains_the_entry_and_reports_incomplete` |
| a later retry positively reaps and completes | `test_a_later_retry_positively_reaps_and_completes` |
| an absent cgroup with an unreaped child is incomplete | `test_cgroup_removal_with_an_unreaped_owned_child_stays_incomplete` |
| `ECHILD` without evidence stays unresolved | `test_echild_without_trusted_evidence_stays_unresolved` |
| `ECHILD` with exact evidence is accepted | `test_echild_with_exact_trusted_evidence_is_accepted` |
| a late joiner is still handled truthfully | `test_a_process_that_joins_after_the_snapshot_is_still_handled_truthfully` |
| an unrelated member is never waited on | `test_a_member_that_is_not_this_controllers_child_is_never_waited_on` |
| an exact owned PID is reaped once | `test_an_exact_owned_pid_is_reaped_once` |
| containment and reap are separate fields | `test_containment_and_reap_are_separate_evidence_fields` |
| capacity counts reservations and entries | `test_the_capacity_counts_reservations_and_entries_together` |
| the sixty-fifth obligation is refused | `test_the_sixty_fifth_obligation_is_refused` |
| a direct `record` cannot exceed the capacity | `test_direct_record_cannot_exceed_the_capacity` |
| concurrent reservations at 63 allow exactly one | `test_concurrent_reservations_at_sixty_three_allow_exactly_one_more` |
| concurrent records never exceed the capacity | `test_concurrent_records_never_exceed_the_capacity` |
| a reservation converts exactly once | `test_a_reservation_converts_exactly_once` |
| a reservation is released on clean completion | `test_a_reservation_is_released_on_a_clean_completion` |
| a cgroup reserves before it creates the directory | `test_a_cgroup_reserves_before_it_creates_the_directory` |
| a forked child trusts no parent reservation | `test_a_forked_child_trusts_no_parent_reservation_or_entry` |
| concurrent registry operations stay coherent | `test_concurrent_record_remove_and_evidence_stay_coherent` |
| a registrar exception cannot lose a cgroup obligation | `test_a_registrar_exception_cannot_lose_a_cgroup_obligation` |
| a registrar exception cannot lose a helper obligation | `test_a_registrar_exception_cannot_lose_a_helper_obligation` |
| two simultaneous releases call the owner once | `test_two_simultaneous_releases_call_the_owner_once` |
| a failed owner release leaves the reference unspent | `test_an_owner_release_that_raises_leaves_the_reference_unspent` |
| concurrent helper close and drain settle once | `test_concurrent_helper_close_and_drain_reap_and_release_once` |
| concurrent cgroup close and drain remove once | `test_concurrent_cgroup_close_and_drain_remove_once` |
| concurrent failed-start retries settle once | `test_concurrent_failed_start_retries_settle_once` |
| two drains cannot claim the same entry | `test_two_drains_cannot_claim_the_same_entry` |
| a stale drain cannot remove a newer entry | `test_a_stale_drain_cannot_remove_a_newer_generation_entry` |
| nested registry and handle operations do not deadlock | `test_nested_registry_and_handle_operations_do_not_deadlock` |
| two slow entries share one total budget | `test_two_slow_entries_share_one_total_budget` |
| 64 entries cannot multiply the configured bound | `test_sixty_four_entries_cannot_multiply_the_configured_bound` |
| later entries receive less or zero time | `test_later_entries_receive_less_or_zero_time` |
| an already-expired drain blocks on nothing | `test_an_already_expired_drain_blocks_on_nothing` |
| a repeated drain is a new caller-owned operation | `test_a_repeated_drain_is_a_new_caller_owned_operation` |
| the drain ledger records the total and exhaustion | `test_the_drain_ledger_records_the_configured_total_and_exhaustion` |
| no float appears in durable deadline evidence | `test_no_float_appears_in_the_durable_deadline_evidence` |
| delegated physical: a real replacement is never signalled | `test_a_real_replacement_cgroup_is_never_signalled` |
| delegated physical: a real delayed reap holds the obligation | `test_a_real_delayed_reap_keeps_the_obligation_until_it_happens` |
| delegated physical: real capacity exhaustion refuses | `test_real_capacity_exhaustion_refuses_a_real_effect` |
| delegated physical: a real concurrent close and drain | `test_a_real_concurrent_close_and_drain_settle_once` |
| delegated physical: a real multi-entry bounded drain | `test_a_real_multi_entry_drain_shares_one_deadline` |
| delegated physical: the nominal path is unchanged | `test_a_nominal_effect_completes_and_retains_nothing` |
