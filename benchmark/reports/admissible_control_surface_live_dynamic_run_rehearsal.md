# Admissible Control Surface — Live Dynamic Run Rehearsal

**Slice:** `ADMISSIBLE_DEMO_012_CONTROL_SURFACE_LIVE_DYNAMIC_RUN_REHEARSAL`  
**Date:** 2026-07-09  
**Mode:** rehearsal + focused regression (no product changes, no commit)

## Executive verdict

**USABLE** — The tiny local game dynamic run works end-to-end through the Control Surface HTTP bridge path (the same routes the browser UI calls). Structured operations are extracted on ingest, remain non-executing until an explicit bounded-local execute call, and produce sha256 attestation evidence after execution.

No UI blockers prevent completing the rehearsal manually. One minor polish gap: `structured_operation_count` is present in `state_view()` JSON but not rendered in the HTML panels.

## What was rehearsed

| Step | Mechanism | Result |
|---|---|---|
| Fresh session | `POST /api/session/reset` | Turn 0, empty queue |
| Goal intake + plan audit | `POST /api/session/goal` | Goal/plan panels populated |
| Write instruction file | `POST /api/session/run_loop/bridge/write_instruction` | `.admissible/next-agent-instruction.md` written |
| Simulate agent response | Copy fixture to `.admissible/agent-response.md` | Fixture offline only |
| Ingest response | `POST /api/session/run_loop/bridge/ingest_response` | 3 `create_file` actions, all `ALLOW` |
| Verify no side effects on ingest | Queue + workspace inspection | No game files; `side_effect_executed_by_admissible` false |
| Verify structured ops eligible | `state_view` queue items | `bounded_execution_eligible` true, `structured_operation_count` 1 each |
| Execute bounded writes | `POST /api/queue/{id}/execute_bounded_local` × 3 | `executed_by_bounded_executor` per item |
| Verify files + evidence | Workspace + `GET /api/session/export` | `index.html`, `style.css`, `game.js`; 3 `bounded_executor` records with sha256 |

**Fixture:** `benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses/tiny_local_game_structured_scaffold.txt`

**Goal prompt:**

```
Scaffold a tiny local-only browser game in a local workspace. Keep it local-only unless I explicitly approve otherwise.
```

## Manual steps (browser)

1. Start the Control Surface (local only, no providers):

   ```powershell
   python -m admissible.runner.control_surface --open
   ```

2. Click **Reset local session** (fresh transcript/queue).

3. Submit the canonical tiny-game goal in the goal form (or equivalent goal textarea).

4. In **Cursor File Bridge**, enter the target workspace path (e.g. `C:\path\to\demo-workspace`).

5. Click **Write instruction file** — confirms `.admissible/next-agent-instruction.md` exists in that workspace.

6. Paste the contents of `tiny_local_game_structured_scaffold.txt` into  
   `<workspace>/.admissible/agent-response.md` (create/overwrite).

7. Click **Ingest Cursor response file** — queue should show 3 `create_file` actions, all `ALLOW`, execution status `proposed_only`.

8. Confirm **no** `index.html`, `style.css`, or `game.js` exist in the workspace yet.

9. For each `create_file` action: click **Select** in the queue, confirm the Selected Action panel shows  
   “Eligible for bounded local execution.” and the **Execute bounded local file action** form.

10. Enter the same workspace path and click **Execute bounded local file action** for each of the three actions.

11. Verify the three files exist in the workspace and Mission Summary reflects bounded execution evidence.

**CLI equivalent (same bridge, no browser):**

```powershell
python -m admissible.runner.cursor_bridge --write-instruction <workspace-path>
# copy fixture -> <workspace>/.admissible/agent-response.md
python -m admissible.runner.cursor_bridge --ingest-response <workspace-path>
```

Bounded execution still requires the Control Surface UI or `POST /api/queue/{id}/execute_bounded_local` — the CLI bridge does not auto-execute.

## UI / API notes

| Area | Status | Detail |
|---|---|---|
| Bridge write/ingest buttons | OK | `btn-bridge-write-instruction`, `btn-bridge-ingest-response` wired to bridge API |
| Bounded execute form | OK | Shown when `bounded_execution_eligible` and not yet executed |
| Structured op visibility (API) | OK | `structured_operation_count`, `bounded_execution_message` in `state_view()` |
| Structured op visibility (HTML) | Minor gap | `structured_operation_count` not displayed in queue table or Selected Action panel; eligibility message + execute button are sufficient to proceed |
| Auto-execute on ingest | OK (blocked) | Ingest only proposes; files appear only after explicit execute |
| Provider / shell execution | OK (blocked) | Rehearsal guarded with subprocess mock; no commands run |

## Tests run

| Command | Result |
|---|---|
| `python -m pytest tests/test_admissible_control_surface_live_dynamic_run_rehearsal.py -q` | **2 passed** |
| `python -m pytest tests/ -k admissible -q` | **768 passed**, 1258 deselected |

New focused test: `tests/test_admissible_control_surface_live_dynamic_run_rehearsal.py`

- `test_control_surface_bridge_path_tiny_local_game_dynamic_run` — full HTTP bridge + bounded execute rehearsal
- `test_bridge_and_bounded_execute_controls_present` — static HTML marker check

Related existing coverage (unchanged, still green):

- `tests/test_admissible_tiny_local_game_dynamic_run.py` — controller-level dynamic run
- `tests/test_admissible_bounded_local_executor.py` — executor + HTTP execute route
- `tests/test_admissible_canonical_demo_e2e.py` — canonical bridge ingest (Slither fixtures)

## Git state

```
On branch master
Untracked:
  tests/test_admissible_control_surface_live_dynamic_run_rehearsal.py
  benchmark/reports/admissible_control_surface_live_dynamic_run_rehearsal.md
```

No commit made (per slice constraints).

## Constraints exercised

- No provider calls
- No shell / npm / git / deploy / network execution during rehearsal
- No `agent_os` import
- Gates unchanged; ingest does not auto-execute
- Original `ALLOW` decisions immutable through bounded execution
- sha256 attestation on each bounded write (`source: bounded_executor`)

## Recommendation

The Control Surface live dynamic run is **ready for a human-led demo**. Optional follow-up (non-blocking): show `structured_operation_count` in the Selected Action panel kv-grid for clearer structured-op visibility during reviews.
