# M2 Transactional Export Specification

Branch: `paired-runner/m2-fourth-critical-repair-retry`
Starting commit: `1133d131c75ed07e79d949b6b3f2f40847a3218b`
Closes: **M2-B27**

## 1. Defect

Export reservation existed only in memory. Concurrent source mutation during
export could finish as `APPLIED` with the independent mutation lost. Crash
evidence used in-process simulation rather than genuine process restart.

## 2. Durable reservation (before first mutation)

Published at `durable_root/export/<reservation_id>/reservation.json` with
no-replace semantics:

- causal identities (run, session, proposal, decision, reservation, effect);
- authorized-source snapshot identity;
- private execution-view identity;
- exact ordered change set with per-operation expected pre-state and intended
  post-state;
- content fingerprints;
- export protocol/schema version;
- documented durability barrier order.

## 3. Operation journal and barriers

1. Write temporary reservation; fsync file; link no-replace; fsync directory.
2. For each operation: revalidate expected pre-state; mutate; fsync parent;
   durable progress replace.
3. Verify final full-tree identity.
4. Publish receipt then reconciliation only after committed state is durable.

## 4. Recovery

`recover_export(durable_root, reservation_id)` classifies using only durable
records and filesystem state. Ambiguous or partial exports are never
automatically replayed as fresh. Concurrent mutation refuses `APPLIED`.

## 5. Oracles

- Concurrent mutation: independent process changes a target after admission;
  result must not be `APPLIED` with that mutation lost.
- Crash/restart: separate process terminated at each documented transition;
  fresh recovery process reads only durable state.

## 6. Tests

`tests/test_admissible_paired_runner_m2_fourth_repairs.py::TransactionalExportTests`
