# Admissible Control Surface / Goal Intake — Cold Audit

**Audit date:** 2026-07-08  
**Auditor mode:** report-only (no fixes, no refactors)  
**Baseline commit:** `94e4684` — `fix: align admitted execution fixture with selected actions`  
**Implementation state:** uncommitted (11 untracked files; HEAD unchanged)

## 1. Executive verdict

**PASS_WITH_NOTES**

The slice correctly implements a local, stdlib-only Admissible Control Surface with offline goal intake, deterministic plan generation, independent plan audit, action admission queue, autonomy selector, human decision records, and session import/export — without importing `agent_os`, without provider calls, and without an automatic executor. Thesis boundaries are respected in code and tests.

The main gap is **documentation vs. runtime behavior for autonomy levels L2–L4**: only L0/L1 vs L2+ attestation gating is implemented; L2 “batch approval” and L3 “auto-admit” are described in profiles/docs but not differentiated in `available_human_actions` or queue state transitions. This is not a thesis conflict (no execution leak), but it should be clarified before a demo that promises those semantics.

## 2. Repo state

| Item | Value |
|---|---|
| Branch | `master` |
| HEAD | `94e4684` |
| Committed since baseline | nothing (slice is entirely uncommitted) |
| Staged changes | none |
| Working tree | dirty — 11 untracked implementation files |
| Generated artifacts tracked by mistake | none observed in this slice |

### Untracked files (full slice)

```
admissible/control_surface.py
admissible/goal_intake.py
admissible/plan_audit.py
admissible/runner/control_surface.py
admissible/harness/control_surface.html
docs/admissible-control-surface.md
docs/admissible-autonomy-levels.md
docs/admissible-goal-intake-and-plan-audit.md
tests/test_admissible_control_surface.py
tests/test_admissible_goal_intake.py
tests/test_admissible_plan_audit.py
```

`admissible/admitted_execution.py` predates this slice (committed at `94e4684`) and is correctly reused by the control surface for attestation validation.

## 3. Implementation inventory

| Expected area | Path | Present |
|---|---|---|
| Control surface core | `admissible/control_surface.py` | yes (~732 lines) |
| Goal intake | `admissible/goal_intake.py` | yes |
| Plan candidate + audit | `admissible/plan_audit.py` | yes |
| Runner / CLI | `admissible/runner/control_surface.py` | yes |
| UI harness | `admissible/harness/control_surface.html` | yes (~630 lines) |
| Docs | `docs/admissible-*.md` (3 files) | yes |
| Tests | `tests/test_admissible_{control_surface,goal_intake,plan_audit}.py` | yes (71 tests) |

## 4. Boundary audit

| Check | Result | Evidence |
|---|---|---|
| No `agent_os` import under `admissible/` | **PASS** | `grep` on new modules; `tests/test_admissible_boundary.py` passes |
| No provider / network calls in slice | **PASS** | Static tests in `test_admissible_control_surface.py`; UI `fetch()` only to `/api/*` |
| No shell command executor | **PASS** | No `subprocess`, `os.system`, `eval`/`exec` in slice modules |
| No automatic Cursor/LLM calls | **PASS** | Goal intake + plan audit are keyword/heuristic only |
| UI cannot execute shell commands | **PASS** | Buttons POST JSON to local API; no command runner endpoints |
| Human decisions do not rewrite rules-only decisions | **PASS** | `decide()` appends `HumanDecisionRecord`; `item.decision` unchanged (tested) |
| Admitted execution validation on attestation | **PASS** | `validate_executed_after_admission_record` called in `decide()` for `attest_executed` |
| Autonomy does not override hard gates | **PASS** | `available_human_actions()` unit tests for all levels × decision types |

**Thesis alignment:** Cursor/frontier proposes (trace load + goal form); Admissible frames/audits/admits/records; human decides; no automatic executor in v0. **No thesis conflicts found.**

## 5. Feature audit

### A. Local launch command — **PASS**

```powershell
python -m admissible.runner.control_surface --open
```

- CLI exists with `--help`, `--host`, `--port`, `--open`, `--session-dir`, `--sample-trace`
- Stdlib `ThreadingHTTPServer` + `webbrowser` only
- Blocks until Ctrl+C; session persisted under `.admissible/` (gitignored)
- Default sample trace path points at committed fixture JSON

### B. LLM-like control surface UI — **PASS_WITH_NOTES**

Present:

- Session transcript (`#transcript-log`)
- Autonomy selector (`#autonomy-select`) with profile descriptions
- Goal intake panel (`#goal-intake-panel`)
- Plan + audit panel (`#plan-audit-panel`) — **combined** in one panel (plan candidate + audit verdict both rendered)
- Action admission queue (`#admissible-queue-panel`)
- Human decision controls per queue item (`decide-form`)
- Decision records panel (`#decision-records-panel`)
- Import/export session JSON (export via `/api/session/export`; import via file picker)
- Truth-boundary banner and footer language

Note: audit brief asked for separate plan proposal and plan audit panels; implementation merges them while also logging `plan_proposal` / `plan_audit` in the transcript.

### C. Goal intake — **PASS**

`analyze_goal()` deterministically extracts: task type, deliverable, project maturity, architecture-choice burden, complexity, global risk (+ scope), likely side-effect classes, missing context, clarifying questions, recommended autonomy ceiling, initial non-execution boundary, and auditable `signals`.

### D. Plan candidate — **PASS**

`generate_plan_candidate()` is offline and deterministic with expected step skeleton: inspect workspace → choose architecture → (optional gated install) → create files → implement → verify locally → assess production readiness → gated no-deploy step.

### E. Independent plan audit — **PASS**

`audit_plan()` is separate from `generate_plan_candidate()` (not mutually calling to self-heal). Verdicts: `PLAN_OK_FOR_LOCAL_PROTOTYPE`, `PLAN_NEEDS_CLARIFICATION`, `PLAN_NEEDS_HUMAN_APPROVAL`, `PLAN_BLOCKED`. Checks architecture gating, dependency gates, deployment gate, verification step, missing context.

### F. Autonomy levels — **PASS_WITH_NOTES**

All five stable levels defined with profiles and tests:

- `L0_OBSERVE_ONLY`
- `L1_PROPOSE_ONLY`
- `L2_LOCAL_BATCH_APPROVAL`
- `L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS`
- `L4_HIGH_AUTONOMY_HARD_GATES`

Hard gates (`REFUSE`, `REQUIRE_HUMAN_APPROVAL`, `REQUEST_MORE_EVIDENCE`, `ALLOW_WITH_LIMITS`) are unaffected by autonomy level in code.

**Gap (P2):** Runtime behavior differs only for attestation eligibility (L0/L1 block `attest_executed`; L2+ allow it on eligible `ALLOW`). L2 batch UI and L3 auto-admit-to-`admitted_not_executed` are documented in `AUTONOMY_PROFILES` but not implemented as distinct mechanics.

### G. Human decision records — **PASS**

Records include: `record_id`, `action_id`, `decision_type`, `actor` (`human_operator`), `timestamp`, `scope`, `rationale`, `linked_decision_id`, `linked_envelope_id`. Original `DecisionQueueItem.decision` is never overwritten.

### H. Sample data loading — **PASS**

`load_sample_session()` loads Slither prompt + `benchmark/reports/admissible_cursor_admitted_execution_truth_console_trace.json` (31 actions in manual audit). Fallback to builder fixtures without shell if trace missing (tested).

## 6. Autonomy-level audit (focused)

| Level | Hard gates preserved | Attestation gating | Documented extra behavior implemented |
|---|---|---|---|
| L0 | yes | no attest | observe-only — no controls for REFUSE (correct) |
| L1 | yes | no attest | propose-only — matches code |
| L2 | yes | attest on eligible ALLOW | batch approval — **docs only** |
| L3 | yes | same as L2 | auto-admit — **docs only** |
| L4 | yes | same as L2 | hard gates only — matches code for gates |

Autonomy never weakens admission labels. **No override of REFUSE / REQUIRE_HUMAN_APPROVAL / REQUEST_MORE_EVIDENCE / ALLOW_WITH_LIMITS.**

## 7. Goal-intake audit (focused)

Slither fixture prompt tests pass with expected classifications (software_build, browser game, medium architecture burden, local risk scope, side-effect classes, L2/L3 ceiling never L4). Empty prompt raises `ValueError`. Module is standalone (no `control_surface` import). Conservative heuristics with auditable `signals`.

## 8. Plan-audit audit (focused)

Generation and audit are independent functions. Slither scenario yields `PLAN_NEEDS_CLARIFICATION`. Unsafe plan mutations (ungated deploy, missing dependency step, missing verify) correctly escalate to `PLAN_BLOCKED` or `PLAN_NEEDS_HUMAN_APPROVAL`. Audit does not mutate the plan object.

## 9. Human-decision audit (focused)

- `approve` requires explicit `scope` for `REQUIRE_HUMAN_APPROVAL`
- `limit_scope` requires `scope`
- `REFUSE` Admissible decisions expose zero human actions
- Invalid attestation rejected via `AdmittedExecutionValidationError`; state unchanged
- Export/import round-trip preserves human decisions

## 10. UI / manual launch audit

| Step | Result |
|---|---|
| `python -m admissible.runner.control_surface --help` | OK |
| Ephemeral server: GET `/` serves HTML | 200 |
| POST `/api/session/load_sample` | 31 queue items |
| POST `/api/session/autonomy` | level changes, transcript entry |
| GET `/api/session/export` | 200, JSON session |
| POST `/api/session/goal` | offline intake + audit |
| UI `fetch()` targets | same-origin `/api/*` only |

Server stops cleanly via `server.shutdown()` / Ctrl+C. No background processes left running during audit.

## 11. Test results

### Minimum pytest command

```
python -m pytest tests/test_admissible_control_surface.py \
  tests/test_admissible_goal_intake.py \
  tests/test_admissible_plan_audit.py \
  tests/test_admissible_admitted_execution.py \
  tests/test_admissible_long_run_truth_console.py \
  tests/test_admissible_boundary.py -q
```

**Result:** `115 passed, 26 subtests passed` (~1.7s)

### Full admissible unittest discovery

```
python -m unittest discover -s tests -p "test_admissible_*.py" -q
```

**Result:** `Ran 496 tests` — **OK** (~3.8s)

### New slice tests only

71 tests across the three new test modules — all pass.

## 12. Bugs / risks / thesis conflicts

| ID | Severity | Classification | Finding |
|---|---|---|---|
| R1 | P2 | PASS_WITH_NOTES | L2/L3/L4 share identical `available_human_actions` behavior; batch/auto-admit semantics are doc-only |
| R2 | P2 | PASS_WITH_NOTES | Plan proposal and plan audit share one UI panel (functionally complete) |
| R3 | P2 | FIX_BEFORE_COMMIT | Entire slice is uncommitted at HEAD `94e4684` |
| R4 | P3 | PASS_WITH_NOTES | `test_admissible_goal_intake.test_no_agent_os_import` uses substring `agent_os` ban (brittle vs AST boundary test) |

**Thesis conflicts:** none  
**Blockers:** none

## 13. Recommended next actions

1. **Commit the slice** as one coherent unit (`ADMISSIBLE_CONTROL_SURFACE_AND_GOAL_INTAKE_V0`) — all files listed in §2.
2. **Align autonomy docs or implementation** — either implement L2 batch + L3 auto-admit state transitions, or narrow profile text to “attestation gating only” until a later slice.
3. **Optional demo polish** — split plan proposal vs audit panels if the walkthrough script calls them out separately.

## 14. Non-claims

This audit does **not** claim:

- That goal intake heuristics are production-quality NLU (they are intentionally auditable/offline)
- That L3 auto-admit or L2 batch approval work as documented (they do not in runtime v0)
- That the control surface replaces Cursor or any frontier agent
- That live provider paths elsewhere in the repo were exercised (audit explicitly avoided provider calls)
- That browser visual polish was manually verified pixel-by-pixel (API + HTML structure + tests only)
