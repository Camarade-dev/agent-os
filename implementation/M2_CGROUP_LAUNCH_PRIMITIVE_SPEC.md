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
