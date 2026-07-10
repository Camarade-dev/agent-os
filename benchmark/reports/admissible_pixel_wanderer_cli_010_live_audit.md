# Live audit: pixel-wanderer-cli-010

Session: `pixel-wanderer-cli-010`  
Slice: `ADMISSIBLE_RUN_040_VERIFICATION_REPAIR_CLOSURE_PSEUDO_GATE_AND_EXPORT_FIX`  
Date: 2026-07-10

## What RUN_039 fixed successfully

- Structured extraction routed four concrete `write_file` operations from a single agent response.
- Partial batch drain executed admitted writes without requiring another provider turn between siblings.
- Empty-success explicit retry preserved instruction identity and produced a usable second response.
- Single-flight ticks prevented duplicate backend invocation.
- Acceptance ledger initialized eight browser-game criteria from goal text on run start.

## Why three criteria failed verification

| Criterion | Root cause | Genuine miss vs matcher |
|-----------|------------|-------------------------|
| `required_files` | `LOCAL_DEV.md` never written; model proposed `README.md` instead | **Genuine deliverable miss** — README does not satisfy an explicit mandatory path |
| `game_controls` | Legacy `file_contains` literal `'w'` check failed on `keys.w` property access | **Matcher miss** — cli-010 `game.js` contains WASD via `keys.w`, `keys.a`, `keys.s`, `keys.d` |
| `local_usage` | `LOCAL_DEV.md` missing | **Genuine deliverable miss** (downstream of missing mandatory file) |

### game_controls audit conclusion

Inspected cli-010 `game.js` snippet:

```javascript
if (keys.ArrowUp || keys.w || keys.W) dy -= 1;
if (keys.ArrowDown || keys.s || keys.S) dy += 1;
```

WASD bindings are **present** under property-access syntax. RUN_040 extends `_js_key_present()` to recognize literals, `keys.X`, bracket access, and `e.key ===` comparisons. After the matcher fix, `game_controls` passes without rewriting `game.js`.

## Proposal coverage vs execution

Observed proposal batch:

- **Mandatory proposed/satisfied:** `index.html`, `style.css`, `game.js`
- **Mandatory missing:** `LOCAL_DEV.md`
- **Unmatched additional:** `README.md`

Policy: execute safe admitted partial batch; do **not** treat README as satisfying LOCAL_DEV.md; enter `repair_needed` for uncovered mandatory criteria.

## Pseudo-gate leakage

Aggregate prose:

> Approve bounded execution of the four structured write_file operations below

was classified as `plan_gate_resolution / REQUIRE_HUMAN_APPROVAL`, human-approved, yet remained `admitted_not_executed` and counted as the sole active blocker while the four concrete writes executed independently.

RUN_040 suppresses this pattern at ingest and repairs stale persisted rows on session load via `_repair_stale_aggregate_pseudo_gates()`.

## Missing repair transition (primary closure defect)

After verification:

- zero pending executable operations;
- repairable mandatory failures (`required_files`, `local_usage`);
- provider/work budget remained;

The controller had **no repair transition**. Stale pseudo-gate `active_blocked_count=1` blocked `_can_start_repair()`. Repeated no-progress ticks escalated to `internal_livelock` instead of `repair_needed → write_repair_instruction`.

RUN_040 adds explicit repair phases, targeted repair packets, post-repair re-verification, and treats repair entry as progress for the no-progress detector.

## Export portability failure

Environment diagnostics exported both `SYSTEMROOT` and `SystemRoot`. Python parsed the JSON; PowerShell `ConvertFrom-Json` rejected duplicate keys modulo case.

RUN_040 canonicalizes environment keys before persistence/export and records source aliases separately.

## Null / inconsistent projections

Live export left `outcome`, `pending_useful_operation_count`, `active_blocked_count`, and `blocking_reason` null while mode was `paused / internal_livelock`.

RUN_040 migrates legacy nulls to canonical defaults (`outcome=in_progress`, counts `0`, empty blocking reason).

## Why cli-010 did not complete live

1. Model omitted mandatory `LOCAL_DEV.md` (substituted README).
2. Aggregate pseudo-gate remained an active blocker after human approval.
3. Verification failed on missing file + legacy controls matcher false negative.
4. No repair loop ran; livelock pause masked ordinary verification failure.

## Deterministic replay after RUN_040

Fixture replay path:

1. Ingest partial batch (README present, LOCAL_DEV.md missing) → coverage incomplete, writes execute.
2. Verify → 5/8 pass; repairable failures detected.
3. `repair_needed` → targeted repair instruction (LOCAL_DEV.md only; game.js preserved).
4. Repair ingest + execute + re-verify → **8/8 verified, outcome=completed** without a third provider turn.

## Human intervention metrics

- Raw human decision on aggregate pseudo-gate preserved in audit log.
- `genuine_human_intervention_count` → **0** after retrospective suppression.
- `retrospectively_suppressed_pseudo_gate_decision_count` → **1**.
