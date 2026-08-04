# M2 Runtime Binding Specification

Branch: `paired-runner/m2-private-workspace-and-bound-runtime`
Starting commit: `68dd7c9a6be66319dc93eeedcec2e994a6119585`
Closes: **M2-M22**, **M2-M23**

## 1. Runtime identity must be descriptor-bound

Hashing a pathname at readiness or preflight and later launching that pathname
leaves a replacement window. A same-owner host process may replace the launcher,
interpreter, or in-capsule init after the final recheck and before `Popen` /
mount resolution. The durable evidence would then bind the old digest while the
kernel executes or mounts the new object.

### Required construction

`admissible/paired_runner/runtime_binding.py` opens each runtime input, verifies
its digest and inode identity against `CapsuleRuntimeManifest`, and holds the
descriptors through actual use:

| Input | Bind | Use |
| --- | --- | --- |
| bubblewrap launcher | `O_RDONLY` verified FD | executed as `/proc/self/fd/N` |
| interpreter | verified FD | `bwrap --ro-bind-fd` → `/.admissible-interpreter` |
| in-capsule init | verified FD | `bwrap --ro-bind-fd` → `/.admissible-capsule-init` |
| private execution view | directory FD | `bwrap --bind-fd` → `/workspace` |
| seccomp program | anonymous memfd | `bwrap --seccomp FD` |

PATH substitution cannot redirect the launched object: the launcher is never
re-resolved for exec after the descriptor bind; ambient PATH is consulted only
to detect shadowing at bind time.

### Tests

| Requirement | Test |
| --- | --- |
| verified inode survives pathname replacement | `test_replacement_of_launcher_bytes_after_bind_still_executes_verified_inode` |
| replaced interpreter refused at bind | `test_replaced_interpreter_before_bind_is_refused` |
| effect path uses bound capsule | `test_path_substitution_cannot_redirect_bound_launcher` |

## 2. Cgroup membership before command execution

`EffectCgroup.active` previously meant "directory exists". `attach()` returned
`False` on failure and the return value was ignored. The durable observation
could claim `CGROUP_V2_AND_RLIMIT` without kernel membership.

### Required construction

1. When a cgroup subtree is created, the launcher child is started with
   `preexec_fn` that raises `SIGSTOP` before exec.
2. The controller writes the launcher PID to `cgroup.procs` and reads membership
   back from the kernel.
3. Only after verified membership is the child released with `SIGCONT`.
4. Attachment failure refuses the effect before the launcher image — and
   therefore before the untrusted command — executes.
5. If readiness promised `CGROUP_V2_AND_RLIMIT`, silent degradation to RLIMIT is
   forbidden (`effective_mechanism` returns `NONE` and the supervisor raises
   `ResourceContainmentUnavailable`).
6. Cleanup that finds live members does not report success.
7. RLIMIT remains mandatory defence in depth inside the capsule.

`active` now means directory present **and** membership verified.

### Tests

| Requirement | Test |
| --- | --- |
| directory ≠ membership | `test_directory_existence_is_not_membership` |
| live members block cleanup success | `test_attach_and_verify_requires_procs_membership` |
| no silent degrade when promised | `test_required_cgroup_mechanism_does_not_silently_degrade` |
| readiness matches probe | `test_readiness_mechanism_matches_delegation_probe` |

On the qualification host, cgroup v2 is not delegated; the recorded mechanism is
honestly `RLIMIT`. Aggregate cgroup claims are made only when membership is
verified.
