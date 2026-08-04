# M2 Private Workspace and Trusted Export Specification

Branch: `paired-runner/m2-private-workspace-and-bound-runtime`
Starting commit: `68dd7c9a6be66319dc93eeedcec2e994a6119585`
Closes: **M2-B21**

## 1. The corrected statement

The second repair asserted that workspace admission plus a seccomp denial of
`socket(AF_UNIX)`, `socketpair(AF_UNIX)`, `mknod`, and `mknodat` closed host
IPC. That is false against a live writable bind of the authorized workspace.

A host process may create a FIFO after admission. The seccomp program does not
filter `open`/`openat`, and cannot distinguish opening a FIFO from opening a
regular file once the inode is resolved. The effect can therefore communicate
with a host peer through a late-created FIFO.

**A live writable host bind + preflight special-inode scan + seccomp denial of
endpoint creation is forbidden as a closure claim.**

## 2. The property this specification enforces

> The effect process must not observe or communicate through a host-backed IPC
> endpoint at any instant during execution.

## 3. The chosen design

Every `run_command` effect uses this exact path (DIRECT and GOVERNED ALLOW):

1. Before `STARTED`, materialise the authorized source into a private per-effect
   directory (`PRIVATE_MATERIALIZED_COPY`).
2. Refuse if the source already contains a special inode.
3. Bind the private view into the capsule with `bwrap --bind-fd` at `/workspace`.
4. Run the untrusted command only against that private view.
5. After process-domain quiescence, the trusted controller computes a closed
   change set with descriptor-relative, no-follow operations.
6. If the authorized source mutated since the snapshot, refuse export.
7. If the private view contains unsupported inode types, refuse export.
8. Otherwise apply only regular-file, directory, and in-tree relative symlink
   changes into the authorized workspace.
9. Never export sockets, FIFOs, devices, or other specials.

Seccomp denial of endpoint creation remains defence in depth inside the capsule.
It is not the isolation claim.

## 3a. Fourth-repair supersession (M2-B26 / M2-B27)

The host-named `PRIVATE_MATERIALIZED_COPY` construction and any export path that
publishes a reservation only in memory are superseded by:

- `implementation/M2_PRIVATE_MOUNT_NAMESPACE_SPEC.md` —
  `PRIVATE_MOUNTNS_TMPFS` descriptor-bound private mount;
- `implementation/M2_TRANSACTIONAL_EXPORT_SPEC.md` — durable no-replace
  reservation, operation journal, and separate-process crash/recovery
  classification.

The export grammar and typed records in this document remain normative; the
materialization substrate and durability ordering do not.

## 4. Typed records

| Record | Schema |
| --- | --- |
| `SourceSnapshotIdentity` | `admissible.paired_runner.m2.source_snapshot_identity` |
| `PrivateExecutionViewIdentity` | `admissible.paired_runner.m2.private_execution_view_identity` |
| `ProposedExportChangeSet` | `admissible.paired_runner.m2.proposed_export_change_set` |
| `ExportReservation` | `admissible.paired_runner.m2.export_reservation` |
| `ExportReceipt` | `admissible.paired_runner.m2.export_receipt` |
| `ExportReconciliation` | `admissible.paired_runner.m2.export_reconciliation` |

## 5. Export grammar

Allowed operations: `CREATE_REGULAR_FILE`, `UPDATE_REGULAR_FILE`,
`DELETE_REGULAR_FILE`, `CREATE_DIRECTORY`, `DELETE_DIRECTORY`, `CREATE_SYMLINK`,
`UPDATE_SYMLINK`, `DELETE_SYMLINK`.

Symlink targets must be relative and must not contain `..`. Absolute and
escaping symlinks refuse export.

Partial export is crash-classifiable (`REFUSED_PARTIAL`) and never silently
reported complete.

## 6. Test matrix

`tests/test_admissible_paired_runner_m2_third_repairs.py`

| Requirement | Test |
| --- | --- |
| host FIFO after admission | `test_host_fifo_after_admission_is_invisible_to_the_effect` |
| host FIFO while running | `test_host_fifo_while_command_runs_cannot_carry_bytes` |
| host pathname socket after admission | `test_host_pathname_socket_after_admission_is_unreachable` |
| host source mutation | `test_host_source_mutation_refuses_export` |
| private-layer specials | `test_effect_created_specials_are_not_exported_or_host_visible` |
| ordinary export matrix | `test_ordinary_mutations_export_exactly` |
| unsupported inode refusal | `test_unsupported_inode_refuses_export` |
| export crash oracle | `test_export_crash_oracle_classifies_partial_and_pre_export` |
| private IPC not host-visible | `test_private_ipc_is_not_host_visible_in_authorized_workspace` |

## 7. Withdrawn claim

The second-repair known limitation that "a host process that creates a FIFO in
the workspace mid-execution is outside both mechanisms" is withdrawn as an
accepted limitation. It was the defect. The private execution view closes it.
