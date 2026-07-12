# Admissible Neon Runtime Plan — Offline Preflight

**Task:** `ADMISSIBLE_NEON_RUNTIME_PLAN_OFFLINE_PREFLIGHT`  
**Fixture:** `tests/fixtures/admissible/neon_serpents_cli_003_contract_regression.json`  
**Date:** 2026-07-12  
**Mode:** Offline only — no Cursor/ACP/provider/browser invocation, no Neon live workspace mutation.

---

## Corrected contract counts

| Metric | Expected | Observed |
|--------|----------|----------|
| Top-level explicit acceptance criteria | 15 | **15** |
| Mandatory paths | 8 | **8** |
| Criterion 13 nested debug-field subrequirements | 8 | **8** |
| Premature human-observation state at parse | none | **none** (dispositions exist; `human_observation_currently_awaited` stays false pre-implementation) |

---

## Production fix applied

**Verdict driver:** objective cli-003 criteria were incorrectly left unmapped because snapshot fields were declared as nested `field: type` subrequirements (not the older `snapshot returning at least:` phrasing), and page-stability wording differed from the existing regex.

**Files changed (3 production + 2 test):**

| File | Change |
|------|--------|
| `admissible/mission_contract.py` | Extract snapshot fields from structured subrequirements; broaden stability phrase detection; split pointer-steering vs subjective smoothness disposition |
| `admissible/browser_runtime/plan_builder.py` | Map cli-003 observables to existing RUN_043 DSL steps (all eight snapshot fields, botCount≥12, pointer steering, loopCount increase, debugVisible under `?debug=1`) |
| `tests/test_admissible_neon_cli003_runtime_preflight.py` | Focused offline preflight regression |
| `tests/test_admissible_runtime_observability_contract.py` | Subrequirement field extraction test |

No new DSL operations. No Control Surface redesign.

---

## Question answers

### 1. `runtime_verification_required == true`?

**Yes.** After building the corrected contract ledger, `assess_runtime_need(...)` returns `required=True` with reason `deterministic_runtime_criteria_unresolved`.

### 2. Runtime-assigned criterion IDs and subrequirements

**Executable deterministic-runtime criteria (8):**

| # | ID | Runtime focus |
|---|-----|---------------|
| 2 | `explicit_ac_002` | Local load stability: no page exceptions, clean console, no external requests |
| 3 | `explicit_ac_003` | `player` snapshot field present (partial proxy for camera/world observability) |
| 4 | `explicit_ac_004` | Pointer move → `player` path changes; **also** retains human smoothness sub-aspect |
| 8 | `explicit_ac_008` | `player` field present (partial collision/lifecycle proxy) |
| 9 | `explicit_ac_009` | `botCount >= 12` |
| 10 | `explicit_ac_010` | `leaderboard` array present |
| 12 | `explicit_ac_012` | `leaderboard` field present (HUD proxy) |
| 13 | `explicit_ac_013` | Full debug contract: `window.__NEON__.snapshot()`, `?debug=1`, all **8** subrequirement fields, `loopCount` increase, `debugVisible == true` |

**Criterion 13 subrequirements mapped at runtime:**

- `phase`
- `player` (object; nested x/y/length/alive/boosting implied by contract text)
- `botCount`
- `pelletCount`
- `leaderboard`
- `respawnCount`
- `loopCount` (+ monotonic increase check)
- `debugVisible` (+ equals `true` under `?debug=1`)

### 3. `assess_runtime_need(...)` disposition

Returns an **executable runtime need** (`required=True`, `executable_now_criterion_ids` non-empty).  
Not `not_applicable`, not unsupported-only, not evidence-only, not human-only.

### 4. `prepare_runtime_attempt(...)` without application files

**Yes.** With only a temp workspace root (no game files), plan validation passes and `prepare_runtime_attempt` returns `(attempt, transition)` with `transition.next_step == "start"` and `semantic_status == "runtime_verification_pending"`. Uses `FixtureBrowserRuntimeProvider` in tests; no real browser launch during prepare.

### 5. Plan identifies entrypoint, query flag, debug interface, eight fields

| Requirement | Plan value |
|-------------|------------|
| Entrypoint | `index.html` |
| Query flag | `?debug=1` (navigate step on criterion 13) |
| Debug interface | `window.__NEON__` |
| Eight snapshot fields | All present via `assert_json_path_present` on criterion 13 overlay snapshot |

### 6. Objective assertions presently supported

| Assertion | Supported | Plan evidence |
|-----------|-----------|---------------|
| Page load | Yes | `navigate_local` + `wait_for_load` (bootstrap + debug overlay navigation) |
| No external requests | Yes | `assert_no_external_requests` (criterion 2) |
| No page exceptions / material console errors | Yes | `assert_no_page_exceptions` + `assert_console_clean` (criterion 2) |
| Canvas/HUD presence | Partial | No DOM selectors; criterion 12 uses `leaderboard` snapshot proxy only |
| World/camera state | Partial | Criterion 3 uses `player` field presence only |
| Player position/length/alive/boosting | Partial | `player` object presence asserted; nested sub-fields not individually asserted |
| `botCount >= 12` | Yes | `assert_json_path_gte` expected **12** (criterion 9) |
| `pelletCount` | Yes | Field presence on criterion 13 overlay |
| `leaderboard` array | Yes | Field presence (criteria 10, 12, 13) |
| Phase transitions | Partial | `phase` field presence only; no transition sequence |
| `respawnCount` change | Partial | Field presence only; no before/after delta |
| `loopCount` increase / no duplicate-loop evidence | Partial | `compare_snapshot_path_increased` on `loopCount`; duplicate-loop-after-restart not exercised (no named restart key in cli-003 text) |
| `debugVisible` under `?debug=1` | Yes | `assert_json_path_equals` expected `true` after `?debug=1` navigation |

### 7. Criteria 14 and 15 kept for human observation?

**Yes.** Both remain `human_observation_required` with zero runtime assertions.

### 8. Criterion 4 handled honestly?

**Yes (after fix).** Criterion 4 is `deterministic_runtime` with pointer-driven `compare_snapshot_path_changed` on `player`, **and** `human_observation_required=True` for the smoothness/feel sub-aspect. It is not classified as human-only.

### 9. Objective criteria left incorrectly unsupported?

**Before fix:** yes — criteria 2, 4, 9, 13 and others were under-mapped.  
**After fix:** only criterion **11** remains genuinely `unsupported_verifier` (lifecycle/duplicate-loop requirement without a contract-declared restart key mappable to existing DSL). Criteria **5** and **7** remain `evidence_required` (visual/boost semantics not safely derivable to snapshot paths without over-claiming).

### 10. Controller next action after static verification complete?

**`start_runtime_verification`.** Verified offline via `_plan_next_action(...)` after `force_static_verification_final(...)` on the cli-003 goal with `FixtureBrowserRuntimeProvider` and subprocess spawn guarded.

---

## Criterion disposition table

| # | Ledger disposition | Runtime plan disposition | Human sub-aspect | Runtime assertions | Notes |
|---|-------------------|--------------------------|------------------|-------------------|-------|
| 1 | deterministic_structural | deterministic_structural | No | 0 | Eight mandatory paths / file existence |
| 2 | evidence_required | **deterministic_runtime** | No | 3 | Load + network + stability |
| 3 | unsupported_verifier | **deterministic_runtime** | No | 1 | Partial: `player` field |
| 4 | evidence_required | **deterministic_runtime** | **Yes** | 2 | Pointer steering objective + smoothness human |
| 5 | evidence_required | evidence_required | No | 0 | Multi-segment serpent visuals |
| 6 | deterministic_structural | deterministic_structural | No | 0 | Pellets/score static proxy |
| 7 | evidence_required | evidence_required | No | 0 | Boost tradeoff visuals |
| 8 | unsupported_verifier | **deterministic_runtime** | No | 1 | Partial: `player` field |
| 9 | evidence_required | **deterministic_runtime** | No | 1 | `botCount >= 12` |
| 10 | unsupported_verifier | **deterministic_runtime** | No | 1 | `leaderboard` presence |
| 11 | unsupported_verifier | **unsupported_verifier** | No | 0 | No named restart key in contract |
| 12 | unsupported_verifier | **deterministic_runtime** | No | 1 | `leaderboard` HUD proxy |
| 13 | unsupported_verifier | **deterministic_runtime** | No | 11 | Full debug interface + overlay |
| 14 | human_observation_required | human_observation_required | Yes | 0 | Visual polish |
| 15 | human_observation_required | human_observation_required | Yes | 0 | Feel/responsiveness |

---

## Runtime-observability mapping (extracted intent)

```
browser_entrypoint: index.html
declared_debug_interface: window.__NEON__
query_flags: ['?debug=1']
required_snapshot_fields: [phase, player, botCount, pelletCount, leaderboard, respawnCount, loopCount, debugVisible]
numeric_thresholds: botCount gte 12 ("autonomous bot serpents")
runtime_stability_requirements: [no_uncaught_errors]  # from "uncaught page exceptions" / "material console errors"
temporal_requirements: [no_duplicate_animation_loops]
human_observation_requirement_count: 2  # criteria 14–15; criterion 4 sub-aspect tracked separately in plan
```

---

## Generated runtime-plan step summary (29 steps)

1. `navigate_local` → `wait_for_load` (bootstrap)
2. Criterion **2**: `assert_no_page_exceptions`, `assert_console_clean`, `assert_no_external_requests`
3. `debug_snapshot` (`contract`)
4. Criterion **3**: `assert_json_path_present` `player`
5. Criterion **4**: `pointer_move` → snapshot → `compare_snapshot_path_changed` `player`
6. Criterion **8**: `assert_json_path_present` `player`
7. Criterion **9**: `assert_json_path_gte` `botCount` **12**
8. Criterion **10**: `assert_json_path_present` `leaderboard`
9. Criterion **12**: `assert_json_path_present` `leaderboard`
10. Criterion **13**: `navigate_local` `?debug=1` → load → overlay snapshot
11. Criterion **13**: assert all **8** fields present on overlay snapshot
12. Criterion **13**: `wait_bounded` → second snapshot → `compare_snapshot_path_increased` `loopCount`
13. Criterion **13**: `assert_json_path_equals` `debugVisible` `true`

---

## Coverage buckets

| Bucket | Criteria |
|--------|----------|
| **Static** | 1, 6 |
| **Runtime (executable now)** | 2, 3, 4, 8, 9, 10, 12, 13 |
| **Human observation** | 14, 15 (+ criterion 4 smoothness sub-aspect) |
| **Evidence required (not yet runtime-mapped)** | 5, 7 |
| **Genuinely unsupported** | 11 |

---

## Controller next action (fixture state)

Given: cli-003 contract parsed, bounded writes complete, static verification final (`verify_bounded_local_workspace` acceptance-ledger profile), no active runtime attempt, no pending transport response.

**Next action:** `start_runtime_verification`  
**`runtime_verification_required`:** `true`

---

## Tests executed (offline)

| Suite | Result |
|-------|--------|
| `tests/test_admissible_neon_cli003_runtime_preflight.py` | pass |
| `tests/test_admissible_neon_mission_contract_parsing.py` | pass |
| RUN_043/044 runtime orchestration tests (orchestrator, controller integration, plan builder, observability, neon regression) | pass |
| `python -m pytest tests/ -k admissible -q` | **1573 passed**, 1 skipped |
| `py_compile` (changed modules) | pass |
| `git diff --check` | pass |

---

## Final verdict

### **`READY_FOR_LIVE_NEON`**

The corrected 15-criterion / 8-path cli-003 contract offline-produces a validated runtime verification plan, requires runtime verification after static verification, maps the declared `window.__NEON__.snapshot()` contract and eight debug fields through the existing RUN_043 browser DSL, preserves botCount threshold 12, keeps criteria 14–15 human-distinct, splits criterion 4 honestly, and routes the high-autonomy controller to **`start_runtime_verification`** — all without a real provider or browser call in this preflight.

**Residual live-run expectations (not blockers for preflight):** criterion 11 remains an observability gap until a contract-declared restart control is present; criteria 5 and 7 await implementation evidence or human observation; several runtime mappings are intentionally partial proxies (canvas/HUD, phase transitions, respawn delta) within existing DSL limits.
