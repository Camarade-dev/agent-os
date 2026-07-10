# Live audit: pixel-wanderer-cli-011

Session: `pixel-wanderer-cli-011`  
Slice: `ADMISSIBLE_RUN_041_NEGATION_AWARE_ACTION_EXTRACTION_REPAIR_UNBLOCK_AND_RESTART_VERIFICATION`  
Date: 2026-07-10

## What RUN_040 validated successfully

- Callable Cursor Agent CLI using model Auto produced one usable response.
- Four structured `write_file` operations extracted and executed (`index.html`, `style.css`, `game.js`, `LOCAL_DEV.md`).
- Eight deterministic acceptance criteria initialized from goal text.
- Seven criteria reached `verified_pass` after bounded verification.
- Zero pending useful executable operations remained after the write batch.

## Negative-polarity extraction failure

Aggregate safety prose (bullet list item):

> No shell commands, npm/pip installs, git push, deploy, or network calls.

was classified as `action_type=git_push`, `decision=REQUIRE_HUMAN_APPROVAL`. Keyword presence (`git push`) was treated as affirmative side-effect intent even though the sentence is a leading `No …` constraint list.

The operator approved this false candidate. It remained `lifecycle_status=admitted_not_executed` and counted as the sole active blocker (`active_blocked_count=1`).

RUN_041 adds bounded polarity classification: negated constraint prose is suppressed at ingest; stale persisted rows are repaired on session load.

## Phantom blocker effect on repair eligibility

After verification:

- `game_restart` was the only mandatory failure;
- repair budget and work turns remained (`turns_remaining=11`, `max_repair_rounds=2`);
- zero pending useful operations;

The controller did **not** enter `repair_needed` because `active_blocked_count=1` from the false git_push row blocked `_can_start_repair()`. Outcome finalized `incomplete` with `genuine_human_intervention_count=1`.

RUN_041 excludes suppressed non-actions and `admitted_not_executed` approval stubs from canonical active blockers.

## game_restart audit (exact cli-011 `game.js`)

Inspected live `game.js`:

```javascript
window.addEventListener('keydown', (e) => {
  keys[e.key] = true;
  if (e.key === 'r' || e.key === 'R') init();
});
```

| Subcheck | Present? | Evidence |
|----------|----------|----------|
| `r_key_binding_present` | **Yes** | `e.key === 'r' \|\| e.key === 'R'` |
| `restart_handler_present` | **Yes** | `init()` invoked on R |
| `player_state_reset_present` | **Yes** | `init()` resets `player` position |
| `score_reset_present` | **Yes** | `score = 0` in `init()` |
| `collectible_or_game_state_reset_present` | **Yes** | `collectibles = spawnCollectibles()` in `init()` |

**Classification: present, matcher-missed.** Legacy `file_contains` required the literal substring `restart`; cli-011 uses `init()` instead. Restart behavior is functionally present.

RUN_041 replaces the opaque check with `game_restart_check` bounded subchecks. Deterministic replay should pass 8/8 without a repair provider turn.

## Why cli-011 did not complete live

1. Negative constraint sentence mis-extracted as `git_push` side effect.
2. Human approval left a phantom `admitted_not_executed` blocker.
3. Repair state machine refused `repair_needed` while `active_blocked_count=1`.
4. `game_restart` failed only because the legacy matcher required the word `restart`.

## Deterministic replay after RUN_041

1. Ingest four structured writes + negative constraint prose → four actions, zero side-effect candidates.
2. Load/repair stale false git_push → `active_blocked_count=0`, `genuine_human_intervention_count=0`.
3. Verify → `game_restart_check` passes on existing `game.js` → **8/8 verified, outcome=completed** without another model call.

## Human intervention metrics (canonical after fix)

- `raw_human_decision_count` → **1** (audit preserved)
- `genuine_human_intervention_count` → **0**
- `retrospectively_suppressed_non_action_decision_count` → **1**
