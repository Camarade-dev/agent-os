# M2 Private Mount Namespace Specification

Branch: `paired-runner/m2-fourth-critical-repair-retry`
Starting commit: `1133d131c75ed07e79d949b6b3f2f40847a3218b`
Closes: **M2-B26**

## 1. Defect

A host-visible `tempfile.mkdtemp` private copy is pathname-reachable by another
process under the controller’s UID. That peer can plant a FIFO or mutate the
effect view while the command runs.

## 2. Required construction

1. A long-lived helper enters a private user+mount namespace.
2. The parent writes the child’s uid/gid maps.
3. The helper mounts a tmpfs at a helper-local staging path
   (`PRIVATE_MOUNTNS_TMPFS`).
4. The helper sends an open directory FD to the controller via SCM_RIGHTS.
5. Materialization and trusted export use descriptor-relative operations on that
   FD.
6. The capsule launcher is started inside the helper so `bwrap --bind` of the
   helper-local staging path mounts the private tmpfs (host-side
   `--bind-fd` cannot).
7. Cleanup terminates the helper and leaves no reachable mount or live process.

## 3. Invariants

- The host mount namespace exposes no stable pathname for the writable view while
  execution is active (`host_can_pathname_reach(view_fd) is False`).
- Same-UID host peers cannot alter the mounted effect view by pathname.
- The authorized source remains immutable to the effect; export is the only
  trusted mutation path after quiescence.

## 4. Tests

`tests/test_admissible_paired_runner_m2_fourth_repairs.py::PrivateMountIsolationTests`
