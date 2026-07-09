# Admissible Demo Readiness — Post-Slices Report

- **Date:** 2026-07-09
- **Branch / HEAD:** `master` @ `f26224d` (working tree clean at report time)
- **Method:** static review of slices 001–006, regression test execution, extraction-lab
  re-run. No provider calls, no execution of agent-proposed commands, no product code
  changed by this report.

---

## 1. Executive verdict

## **`DEMO_READY_WITH_SCRIPTED_LIMITS`**

The canonical blank-session supervised-loop demo path now completes coherently
offline: human decisions produce visible derived state, attention counts decrease,
instruction packets acknowledge resolved gates, evidence accumulates without
regression, bridge duplicate ingestion is blocked, and session state survives
HTTP/CLI restarts. **694** admissible tests pass, including a pinned canonical
end-to-end regression.

This is **not** full `DEMO_READY`. The demo remains **offline and scripted**:
committed pasted-agent-response fixtures stand in for live Cursor/frontier-agent
output; Admissible still does **not** execute side effects; side-effect execution
remains external and can be attested later; and **live provider integration is
outside this readiness claim**.

---

## 2. Previous audit verdict

**`NOT_DEMO_READY_P0_STATE_GAPS`** ([admissible_end_to_end_demo_audit.md](./admissible_end_to_end_demo_audit.md), HEAD `75bc672`)

The pre-slice audit found solid extraction, evaluation, bridge mechanics, and
audit trail, but P0 failures at the human-decision application layer:

| Gap | Summary |
|-----|---------|
| G1 | Plan-gate approval never closed gates |
| G2 | Needs-attention buckets/count never decreased |
| G3 | Approved side effects never became `admitted_not_executed` |
| G4 | Evidence re-evaluation forgot earlier supplies |
| G5 | Stale/duplicate bridge responses duplicated the queue |

At audit time: **647** admissible tests passed; no canonical blank-session e2e
regression existed.

---

## 3. New demo readiness verdict

| Field | Value |
|-------|-------|
| **Verdict** | `DEMO_READY_WITH_SCRIPTED_LIMITS` |
| **Claim boundary** | Offline supervised-loop demo over committed fixtures and local Control Surface APIs. No live model/provider behavior claimed. No automatic execution claimed. |
| **Not claimed** | Full `DEMO_READY`, live Cursor integration, frontier-model fidelity, side-effect execution by Admissible |

**Why not full `DEMO_READY`:** the supervised demo still depends on pasted
fixtures, a human operator copying bridge files (or running bridge CLI helpers),
and external execution for any admitted side effect. Live provider wiring,
adversarial extraction, and production-grade session concurrency were never in
scope for slices 001–006.

---

## 4. What changed across slices 001–006

### Slice 001 — `ADMISSIBLE_STATE_LIFECYCLE_001_HUMAN_DECISION_APPLICATION`

**Closes G1, G2, G3** (and packet follow-through from original slice 2).

- Append-only `derived_lifecycle_resolutions` and `resolved_plan_gates` on the session.
- `approve` on `plan_gate_resolution` → `lifecycle_status=resolved_gate`; gate ids
  removed from unresolved lists and attention buckets.
- `approve` on side-effecting `REQUIRE_HUMAN_APPROVAL` actions →
  `execution_status=admitted_not_executed`, `lifecycle_status=admitted_not_executed`.
- `refuse` → `refused_closed`; refused items leave needs-attention.
- `needs_attention_count` and buckets driven by `queue_item_needs_attention()`
  (lifecycle-aware), not decision label alone.
- Original admission decision dicts remain immutable.

### Slice 002 — `ADMISSIBLE_STATE_LIFECYCLE_002_EVIDENCE_ACCUMULATION_AND_REEVALUATION`

**Closes G4**; partially addresses G7.

- `provide_evidence` re-evaluates against the **original envelope + all evidence
  records** for the action (ordered fold).
- `missing_evidence` shrinks monotonically across supplies; no regression of
  earlier satisfied types.
- Derived lifecycle statuses: `evidence_supplied_still_blocked`,
  `evidence_satisfied_pending_human_decision`.
- Original envelope and decision remain immutable; evidence records are append-only.

### Slice 003 — `ADMISSIBLE_BRIDGE_003_RESPONSE_FRESHNESS_AND_DUPLICATE_BLOCKING`

**Closes G5**.

- `write_next_instruction` archives an existing `agent-response.md` to
  `agent-response.turn<N>.archived.md`.
- Byte-identical re-ingest raises `DuplicateResponseError` by default; transcript
  records `bridge_ingest_blocked` with `reason=duplicate_response`.
- Framed as ingestion hygiene, not an admission gate (bridge-state remains
  diagnostic-only).

### Slice 004 — `ADMISSIBLE_CONTROL_SURFACE_004_SESSION_PERSISTENCE_PARITY`

**Closes G8**.

- HTTP `build_controller` resumes persisted `session.json` the same way CLI
  `cursor_bridge.build_controller` does.
- Server restart no longer silently discards an on-disk session.
- Invalid session files raise `InvalidSessionFileError` instead of silent reset.
- `fresh_session=True` remains an explicit opt-out for deliberate blank starts.

### Slice 005 — `ADMISSIBLE_DEMO_005_CANONICAL_E2E_REGRESSION`

- Pins the full canonical blank-session scenario from the original audit as
  `tests/test_admissible_canonical_demo_e2e.py`.
- Asserts gate resolution, packet wording, cumulative evidence, admitted-not-executed
  push approval, duplicate-ingest blocking, export/import round-trip, and
  `side_effect_executed_by_admissible=false`.

### Slice 006 — `ADMISSIBLE_UI_006_DEMO_CLARITY_PASS`

**UI follow-through for G2** and demo narrative clarity.

- Supervised Run State renders lifecycle buckets: pending, resolved plan gates,
  admitted-not-executed, refused/closed, evidence-supplied-still-blocked,
  evidence-satisfied-pending-human-decision.
- Per-row lifecycle labels in attention buckets and selected-action panel.
- Persistent no-execution banner; bridge-blocked banner for duplicate ingest.
- Resolved gates shown under "Human-resolved plan gate:" — not repeated as
  unresolved blockers.
- Progressive disclosure: mission summary and queue before collapsible transcript.
- Static HTML tests in `TestControlSurfaceHtmlContent` pin all of the above.

**Also delivered (original audit slice 5 — gate-id plumbing):** `plan_gate_closes_gates()`
and `_closes_gates_for_item()` resolve gate ids from ingested plan-gate text;
closure records reference the correct `gate_id`s even though candidates do not
yet carry a dedicated `plan_gate` sub-dict on the envelope (G6 functional fix,
schema polish remains optional).

---

## 5. Evidence from tests

| Check | Result |
|-------|--------|
| `git status` | clean at report time |
| `python -m pytest tests/ -k admissible -q` | **694 passed**, 1258 deselected, 154 subtests passed (~9.4s) |
| `python -m pytest tests/test_admissible_canonical_demo_e2e.py -q` | **2 passed** (~0.3s) |
| Extraction lab (6 slither-demo fixtures) | **6/6 passed** |
| Provider / network calls during tests | none |
| Automatic side-effect execution | none (`subprocess.run` patched in canonical e2e) |

**Key test modules covering slice behavior:**

| Module | Coverage |
|--------|----------|
| `tests/test_admissible_state_lifecycle.py` | Slices 001–002: gate approval, admitted-not-executed, attention decrease, evidence accumulation |
| `tests/test_admissible_cursor_bridge.py` | Slice 003: archive-on-write, duplicate refusal |
| `tests/test_admissible_control_surface.py` | Slice 004: session resume parity; Slice 006: HTML clarity contracts |
| `tests/test_admissible_canonical_demo_e2e.py` | Slice 005: full offline demo regression |

**Delta from pre-slice audit:** +47 admissible tests (647 → 694), including the
canonical e2e walk and lifecycle/bridge/UI clarity regressions that previously
existed only as proposed tests in the audit.

---

## 6. Canonical demo path now supported

Offline blank-session flow (fixtures in
`benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses/`):

```
1. Start Control Surface (HTTP or in-process controller)
2. Submit goal: Slither-like game, local-only unless explicitly approved
3. Intake → plan → independent audit (required gates, clarifying questions)
4. Bridge write → .admissible/next-agent-instruction.md
5. Paste/simulate agent response: cursor_plan_gate_resolution_request.txt
6. Bridge ingest → plan_gate_resolution queued (REQUIRE_HUMAN_APPROVAL)
7. Human approve plan gate (scope: local_workspace_only)
   → resolved_gate; needs_attention_count decreases; gate absent from next packet
8. Bridge write + ingest negative_only_boundaries.txt (no spurious ALLOW)
9. Bridge write + ingest multi_action_install_push_local_claim.txt
10. Provide evidence A (package_trust_review) then B (license_compatibility)
    → cumulative, no missing_evidence regression
11. Human approve git_push (scope: local_workspace_only)
    → admitted_not_executed; still no file written by Admissible
12. Duplicate re-ingest blocked (DuplicateResponseError + transcript diagnostic)
13. Export session JSON → import round-trip preserves derived state
```

**Invariant throughout:** `any_executed_by_admissible=false`; original decision
labels immutable; human decisions append-only.

---

## 7. Remaining scripted limits

These are **explicit boundaries** of the current demo, not bugs to hide:

| Limit | Detail |
|-------|--------|
| **Offline / scripted** | Agent responses come from committed `.txt` fixtures, not a live Cursor session |
| **No provider calls** | Control Surface and bridge never contact OpenAI, Anthropic, Cursor APIs, etc. |
| **No Admissible execution** | Admissible does not run `npm install`, `git push`, file edits, or shell commands |
| **External execution** | Admitted actions are executed (if at all) by a human or external tool outside Admissible; `attest_executed` records that fact later |
| **Bridge is manual** | Operator copies instruction to agent and response back (or uses `cursor_bridge` CLI helpers); no autonomous agent loop |
| **Single-operator local session** | No multi-user concurrency guarantees |
| **Rules-only evaluator on extracted envelopes** | Extraction quality and evaluator coverage beyond the 6 slither fixtures are not part of this claim |
| **Live provider integration** | Wiring a real frontier model behind `ModelClient` is follow-on work, outside this verdict |

---

## 8. Remaining non-blocking gaps

P0 gaps G1–G5 and G8 are closed. The following P1/P2 items from the original
audit remain but do **not** block the scripted supervised demo:

| Gap | Sev | Status | Impact on scripted demo |
|-----|-----|--------|-------------------------|
| G7 | P1 | Partial | `install_dependency` can remain `REQUEST_MORE_EVIDENCE` with `evidence_supplied_still_blocked` after all fixture-addressable evidence types are supplied (`reversibility` / `business_authority` unknown signals). Demo script approves `git_push` separately; install lane need not converge to ALLOW on camera. |
| G6 | P1 | Functional | Gate ids resolved via `plan_gate_closes_gates()` at decision time; candidate dict still lacks a dedicated `plan_gate` metadata block (schema polish only). |
| G9 | P2 | Open | `decide(request_evidence)` is record-only; no lifecycle transition. Not on the canonical demo path. |
| G10 | P2 | Open | `limit_scope` → `limited_scope_selected` does not propagate scope into next packet `allowed_scope`. Canonical demo uses `approve` with explicit scope. |
| G11 | P2 | Open | Agent evidence responses (`evidence_response_for_request_more_evidence.txt`) ingest as unlinked `verification_plan` items. Canonical demo uses human evidence forms instead. |
| G12 | P2 | Open | Repeat `approve` on an already-resolved item appends another record without guard. Operator discipline suffices for demo. |

---

## 9. Recommended live demo script

**Runtime:** ~8–10 minutes. **Audience:** technical mentor, reviewer, or investor
conversation about supervised admission — not a benchmark claim.

**Setup (before screen share):**

```powershell
python -m admissible.runner.control_surface --open
```

Confirm the no-execution banner is visible. Optionally prepare a temp workspace
with `.admissible/` for bridge files.

**Opening (30s):** "Cursor proposes; Admissible frames, audits, admits, and records
— it does not execute. What you'll see is a local, offline supervised loop. Agent
responses are pasted fixtures standing in for Cursor; nothing here calls a live
model or runs commands."

**Beat 1 — Goal intake (45s):** Submit the Slither local-only goal. Point to plan
audit required gates and risk ceiling. Emphasize immutable audit vs derived human
resolution.

**Beat 2 — Bridge + plan gate (90s):** Write instruction, paste
`cursor_plan_gate_resolution_request.txt`, ingest. Show one `plan_gate_resolution`
queued. Approve with scope `local_workspace_only`. **Key moment:** "Needs you now"
count drops; resolved gate appears in Supervised Run State; next packet shows
"Human-resolved plan gate" instead of repeating the blocker.

**Beat 3 — Boundaries (30s):** Ingest `negative_only_boundaries.txt`. Show no
spurious ALLOW for install/push/deploy — negation respected.

**Beat 4 — Multi-action + evidence (90s):** Ingest `multi_action_install_push_local_claim.txt`.
Supply two evidence types for `install_dependency`. Show missing list shrinks
without regressing; original decision label unchanged.

**Beat 5 — Admit side effect (60s):** Approve `git_push` with local scope. Show
"Admitted, not executed" tile and bucket. Explicitly state: Admissible admitted
the action boundary; execution would happen outside this tool; attest comes later.

**Beat 6 — Hygiene + export (45s):** Attempt duplicate re-ingest; show blocked banner
and transcript entry. Export session JSON; mention restart-safe persistence.

**Closing (30s):** Restate claim boundary — architecture and supervised state
machine proven offline; live frontier behavior and execution attestation are
separate next steps.

**If challenged:** point to `benchmark/reports/admissible_end_to_end_demo_audit.md`
(pre-slice gaps), this report (post-slice closure), and
`tests/test_admissible_canonical_demo_e2e.py` (repeatable regression).

---

## 10. Recommended next implementation work after demo

Priority order after the scripted demo ships:

1. **Live provider behind `ModelClient`** — re-run comparison/trace pipeline with
   real frontier output; keep admission decisions rules-only.
2. **G7 evidence-lane closure** — human supersede path or evidence types that
   satisfy `reversibility` / `business_authority` unknown signals without weakening
   original decisions.
3. **G11 agent-evidence linkage** — optional human-confirmed link from agent
   evidence responses to the gated action they answer.
4. **G9/G10/G12 polish** — visible `request_evidence` transition, scope propagation
   to packets, approve idempotence.
5. **G6 schema** — carry `plan_gate` metadata on candidates for cleaner closure
   auditing.
6. **Extraction lab expansion** — mixed turn fixture (gate close + follow-up action),
   duplicate-turn bridge lab fixture (proposed in original audit §7).
7. **Paired-run video slice** — frontier-direct vs Admissible-gated comparison
   (separate from Control Surface demo).

---

## 11. Final risk assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Demo operator double-clicks ingest | **Low** | Duplicate blocked with visible banner; covered by e2e regression |
| Audience expects live Cursor | **Medium** | Open with explicit fixture boundary; truth-boundary collapsible in UI |
| Audience expects Admissible to run commands | **Medium** | Persistent no-execution banner; admit-not-executed language; no files created |
| Server restart mid-demo loses session | **Low** | Slice 004 parity; session.json resume tested |
| Approved item still looks "pending" | **Low** | Closed by slices 001+006; count decreases in regression |
| Evidence lane appears stuck on install | **Low** | Script focuses on gate + push approval; install stays blocked by design (G7) |
| Live model behaves differently than fixtures | **High (out of scope)** | Not claimed; document as follow-on |
| Accidental execution outside demo | **Medium** | Admissible never executes; operator must not run admitted commands during demo unless illustrating external execution |

**Overall:** acceptable for a **scripted, offline** supervised-loop demo. Residual
risk concentrates on audience expectations about live agents and execution — both
explicitly outside this verdict.

---

## Diagnostics run for this report

| Command | Result |
|---------|--------|
| `git status` | clean |
| `python -m pytest tests/ -k admissible -q` | 694 passed |
| `python -m pytest tests/test_admissible_canonical_demo_e2e.py -q` | 2 passed |
| Extraction lab | 6/6 fixtures passed |

**Files changed by this report:** `benchmark/reports/admissible_demo_readiness_post_slices.md` only.

**Committed:** no.
