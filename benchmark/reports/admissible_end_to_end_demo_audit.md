# Admissible End-to-End Demo Readiness Audit

- **Date:** 2026-07-09
- **Branch / HEAD:** `master` @ `75bc672` (working tree clean at audit start)
- **Method:** static code audit + an offline driver script that executed the full
  canonical demo scenario from a blank `ControlSurfaceController` session using
  in-process `admissible` APIs and the committed pasted-agent-response fixtures.
  No provider calls, no execution of any proposed action, no `agent_os` import,
  no repo state mutated (temp session dir + temp workspace). No product code
  was changed by this audit.

---

## 1. Executive verdict

## **`NOT_DEMO_READY_P0_STATE_GAPS`**

Extraction, evaluation, the bridge file mechanics, and the append-only audit
trail are solid (647 admissible tests pass; extraction lab 6/6). The demo
breaks at the **human-decision application layer**: recording a human decision
never derives any downstream state. Concretely, from a blank session the demo
stalls at steps 6–9 of the canonical scenario:

- approving a decision-only plan gate leaves it `approval_supplied_pending_reevaluation` forever;
- the next instruction packet repeats every gate verbatim as "Unresolved plan gate";
- "Needs Attention" / "Needs you now" never shrink, no matter what the human decides;
- an approved side-effecting action never becomes `admitted_not_executed`;
- supplying evidence one piece at a time **loses previously supplied evidence**
  (re-evaluation bug), so the evidence lane can never converge;
- a stale response file survives the next instruction write and re-ingests
  successfully (warn-only), creating exact duplicate queue items.

The first four are conceptual missing behavior; the evidence loss is an
implementation bug; the stale-response issue is a bridge-hygiene gap that will
bite a live demo operator on the first double-click.

## 2. Canonical end-to-end flow audited

Blank session → submit goal ("Build a small browser-based Slither-like game…
local-only unless I explicitly approve otherwise") → intake/plan/audit →
bridge writes `.admissible/next-agent-instruction.md` → fixture-simulated
Cursor responses (plan-gate, multi-action, evidence, negative-only) →
ingest → human resolves plan gate (approve, scope `local_workspace_only`) →
next packet → human evidence for REQUEST_MORE_EVIDENCE → human approves
side-effecting action → export session JSON.

## 3. Observed vs expected behavior (driver run, blank session)

| Step | Expected | Observed |
|---|---|---|
| 1–2 Goal intake / plan / audit | Intake, plan, independent audit, gates | ✅ `software_build`, risk `local`, ceiling `L2`, verdict `PLAN_NEEDS_CLARIFICATION`, 3 required gates (`step_2_choose_architecture`, `step_2b_install_dependencies`, `step_7_no_deploy_without_authorization`), 2 missing-context + 2 clarifying questions |
| 3 Bridge write | Instruction file written, verifiable | ✅ 4,619 bytes, sha256/mtime reported, bridge-state.json written |
| 4–5 Ingest plan-gate fixture | 1 `plan_gate_resolution` / REQUIRE_HUMAN_APPROVAL, queued, not executed | ✅ classified and queued; nothing executed |
| — `Closes gates:` parsed | Gate ids available downstream | ❌ parsed by `_extract_plan_gate_blocks` but **dropped**; candidate carries no `closes_gates` field |
| — Bridge hygiene | New instruction invalidates old response | ❌ `agent-response.md` survives `write_instruction`; re-ingesting the identical file **succeeds with a warning only** and creates an exact **duplicate queue item** (queue 1 → 2) |
| 6 Approve plan gate (scope `local_workspace_only`) | Gate closed/resolved | ❌ lifecycle → `approval_supplied_pending_reevaluation` **forever**; decision stays REQUIRE_HUMAN_APPROVAL (correct — immutable); still listed in `approval_needed`; `unresolved_plan_gates` unchanged; `needs_attention_count` = 2 |
| 7 Next packet | Human-resolved gates shown as resolved, not repeated | ❌ `open_gates_summary` repeats all 3 gates verbatim as "Unresolved plan gate:"; no mention of the human approval or its scope; `queue_summary` reports `REQUIRE_HUMAN_APPROVAL=2` (counts the approved gate and its stale duplicate) |
| 8 Evidence for REQUEST_MORE_EVIDENCE (`install_dependency`) | Appended, original immutable, applied status clear, converges | ⚠️/❌ evidence record appended ✅; original decision immutable ✅; superseding decision recorded ✅; **but each `provide_evidence` re-evaluates the ORIGINAL envelope + only the latest item** — supplying `license_compatibility` brings `package_trust_review` back into `missing`. After all 3 evidences: still REQUEST_MORE_EVIDENCE. Even with all evidence folded in manually (missing=[]), evaluator holds REQUEST_MORE_EVIDENCE on `reversibility=unknown` / `business_authority=unknown` signals human evidence cannot touch, and the item offers no approve path (only `request_evidence`/`refuse`) |
| 9 Approve side-effecting action (`git_push` REQUIRE_HUMAN_APPROVAL) | Becomes admitted-not-executed | ❌ lifecycle → `approval_supplied_pending_reevaluation`; `execution_status` stays `proposed_only`; `admitted_not_executed` is **never set anywhere in the Control Surface** (only the fixture-based admitted-execution protocol produces it); attestation is only ever offered for ALLOW items, so the approved action can never be attested later |
| 10 Export | Coherent append-only history, no side effects | ✅ schema v0, 15 transcript entries, 3 human decisions, 1 evidence record, 1 superseding decision, 3 response records, 3 packets, 3 paired turns, `any_executed_by_admissible=false` |

## 4. Audit answers by area

### A. End-to-end state machine

**Rules-only decision labels** (immutable, correct): ALLOW, ALLOW_WITH_LIMITS,
REQUEST_MORE_EVIDENCE, REQUIRE_HUMAN_APPROVAL, REFUSE.

**Lifecycle statuses** (`admissible/run_loop.py:47-63`):

| Status | Intent | Reality |
|---|---|---|
| `needs_human_input` | intermediate | ✅ intermediate |
| `evidence_supplied_pending_reevaluation` | intermediate (trace-loaded items) | ❌ dead end — nothing ever re-evaluates them |
| `approval_supplied_pending_reevaluation` | intermediate | ❌ **dead end** — no code path consumes an approval; misnamed since no re-evaluation exists for approvals at all |
| `limited_scope_selected` | intermediate | ❌ dead end; the chosen scope is never propagated anywhere |
| `ready_for_next_agent_instruction` | intermediate | ✅ (ALLOW default; evidence re-eval could reach it in principle) |
| `closed` | terminal | ✅ terminal (refuse, attest) |

**Execution statuses:** `proposed_only`, `admitted_not_executed`,
`executed_after_admission`, `blocked`. The Control Surface only ever sets
`executed_after_admission` (attest). `admitted_not_executed` appears in the
Mission Summary tiles and the admitted-execution protocol but **no Control
Surface transition produces it** — the tile is permanently 0 in a live session.

**Decision-type → next-state coverage:**

| Human decision | Next-state rule |
|---|---|
| `attest_executed` | ✅ → closed + executed_after_admission |
| `refuse` | ✅ → closed (but see B: stays in attention buckets) |
| `approve` | ❌ → dead-end pending status; no gate closure, no admitted state |
| `limit_scope` | ❌ → dead-end status; scope not applied |
| `request_evidence` | ❌ **no transition at all** — record-only, indistinguishable from a no-op in the UI |

### B. Human decision application

Decisions are **recorded only, never applied as derived state** — with one
exception (attest_executed) and one partial exception (evidence
re-evaluation, which is buggy, see P0-4). Plan-gate approvals do not close.
Side-effect approvals do not become admitted-not-executed. Refusals do set
`closed`, but because every "Needs Attention" bucket filters by the immutable
decision label (`control_surface.py:_needs_attention`), **a refused-and-closed
item remains listed under "Approval needed"/"Evidence needed"** and keeps
inflating `needs_attention_count`. Scope-limited approvals record the scope
string on the `HumanDecisionRecord` but it never reaches packets, gates, or
queue projections.

### C. Plan gates

- Unresolved gates live in `plan_audit.required_gates` (original audit
  preserved and immutable ✅).
- **There is no store for resolved gates** — no session field, no record type.
- `run_loop._open_gates_summary` and `_needs_attention.unresolved_plan_gates`
  read `plan_audit.required_gates` directly, so resolved gates repeat forever
  in packets and in the UI.
- The builder parses `Closes gates:` into the gate block
  (`long_run_envelope_builder.py:264`) but drops it when building the segment
  (`:656-659`) — the candidate/envelope carries no gate ids, so even a future
  closure feature has nothing to key on.

### D. Cursor bridge

- Stale/duplicate detection: **warn-only by explicit design** ("bridge-state
  is diagnostics only, never a gate"). That doctrine is right for *admission*
  decisions, but ingestion hygiene is not an admission decision — re-ingesting
  a byte-identical response duplicates queue items with fresh action_ids.
- `write_instruction` does **not** archive/invalidate the previous
  `agent-response.md` (observed surviving the write).
- Diagnostics are otherwise strong: path/bytes/sha256/mtime independently
  re-read on both write and ingest; `bridge-state.json` records
  session/turn/sha lineage.
- CLI vs UI: the CLI (`build_controller`) resumes the persisted
  `session.json`; the HTTP server constructs a **fresh** controller that
  ignores the persisted file and silently overwrites it on the first
  mutation. A repo-local persisted session exists right now
  (`control_session_f140bee43a53`, 32 queue items). Restarting the server
  mid-demo loses the session; running CLI and server concurrently forks state.
- Fresh response ingestion updates the session consistently (turn pairing
  observed coherent in export).

### E. Extraction

- Extraction lab: **6/6 fixtures pass** (numbered ops, plan-gate resolution,
  evidence response, multi-action install/push/edit/claim, negative-only,
  freeform-unknown). Structured plan-gate guidance works: the
  `action_gate_<id>` block classifies as `plan_gate_resolution` /
  REQUIRE_HUMAN_APPROVAL with `internal_state_change` side-effect scope.
- Negative-only and vague freeform correctly land on `unknown` /
  REQUEST_MORE_EVIDENCE (never a positive candidate, never silent ALLOW).
- Remaining shape gaps: no fixture for a *mixed* stale/duplicate turn (bridge
  unit tests cover the warning, but the lab has no end-to-end fixture); an
  agent **evidence response** extracts as a *new* `verification_plan` /
  REQUEST_MORE_EVIDENCE item with no linkage to the earlier gated action —
  agent-supplied evidence has no path to the gate it answers (only the human
  evidence form does).
- Labels, side-effect scopes, required approvals, and missing-evidence sets
  are stable and pinned by `expected_extractions.json`.

### F. UI / demo clarity

- Current turn: shown ✅. Bridge is the single canonical top-level workflow ✅.
  "Nothing executed by Admissible" language present ✅.
- **Pending vs done is broken**: attention buckets and `needs_attention_count`
  are decision-label-driven, so approved, refused, and evidence-supplied items
  all remain "pending" indefinitely; the "Needs you now" tile never decreases.
- `attentionActionRows` renders decision + tool only — lifecycle_status is in
  the data (`_attention_row`) but not rendered in the buckets, so an approved
  gate is visually identical to an untouched one.
- "Admitted, not executed" tile can never move off 0 (no producer).
- Human-approved-but-not-executed has no dedicated view; evidence-supplied is
  visible only via the per-item lifecycle code string in the detail panel.
- Next user action is obvious for the happy path (bridge buttons), but after a
  human decision the UI gives no signal that anything progressed — the demo's
  emotional beat ("Admissible acknowledged my approval") is missing.

### G. Tests

- **Covered (all passing):** packet boundaries/wording, autonomy gating
  invariants, decision immutability, attest validation, export/import
  round-trip, bridge file metadata, stale/duplicate *warnings*, CLI turn
  continuity across processes, HTTP routes, UI panel presence, extraction
  regression (6 fixtures), no-execution/no-provider/no-agent_os guards.
- **Missing (all describe currently-absent or broken behavior):** see
  proposed tests below. No test walks the canonical blank-session demo
  end-to-end; no test asserts anything *decreases* after a human decision;
  no test asserts evidence accumulates monotonically.

## 5. Gap table

| # | Sev | Kind | Gap | Where | Observed | Expected |
|---|---|---|---|---|---|---|
| G1 | P0 | conceptual | Plan-gate approval never closes the gate; no resolved-gates store | `control_surface.py:decide`, `run_loop.py:_open_gates_summary` | approval → `approval_supplied_pending_reevaluation` forever; gates repeat in every packet | decision-only gate → closed/resolved; recorded with scope; excluded from unresolved lists |
| G2 | P0 | conceptual + UI | Attention buckets/count filter by decision label only; resolved/refused items never leave | `control_surface.py:_needs_attention`, `_mission_summary`; `control_surface.html` | approved gate still in "Approval needed"; count static | buckets exclude lifecycle closed/approved/supplied; count derived from buckets |
| G3 | P0 | conceptual | Approved side-effecting action never becomes `admitted_not_executed`; can never be attested | `control_surface.py:decide` (approve branch), `available_human_actions` | execution_status stays `proposed_only` | approve → admitted_not_executed; attestation path opens per admitted-execution protocol |
| G4 | P0 | bug | Evidence re-evaluation forgets earlier evidence (re-runs original envelope + latest item only) | `control_surface.py:provide_evidence` → `run_loop.reevaluate_envelope_with_evidence` | 2nd evidence resurrects 1st missing item; can never converge | re-evaluate against original envelope + ALL evidence records for the action |
| G5 | P0 | bridge hygiene | Stale/duplicate response re-ingest proceeds (warn-only); write-instruction never archives old response; duplicates queued | `cursor_bridge.py:ingest_response_file_with_controller`, `write_next_instruction_with_controller` | identical file re-ingested → duplicate queue item | archive response on instruction write; refuse (with explicit override) byte-identical re-ingest — ingestion hygiene, not an admission gate |
| G6 | P1 | bug/missing plumbing | `Closes gates:` parsed but dropped; candidates carry no gate ids | `long_run_envelope_builder.py:656-659` | `closes_gates` absent from candidate | candidate carries a `plan_gate` sub-dict (gate_id, closes_gates, verdict_class, side_effects) |
| G7 | P1 | conceptual | Evidence lane cannot converge even with full evidence (`reversibility`/`business_authority` unknown persist; no human path except refuse) | `evaluator/rules_only.py:_request_more_evidence_signals`, `available_human_actions` | REQUEST_MORE_EVIDENCE with missing=[] | demo-scriptable closure: either evidence types that satisfy those signals, or an explicit human decision that supersedes without weakening the original |
| G8 | P1 | divergence | HTTP server starts fresh and clobbers persisted session; CLI resumes it | `ControlSurfaceController.__init__` vs `cursor_bridge.build_controller` | repo has a live 32-item persisted session the server would silently discard | one resume policy, shared by both entry points |
| G9 | P2 | ambiguity | `decide(request_evidence)` is record-only; no state change | `control_surface.py:decide` | lifecycle unchanged | either drop the decision type or give it a visible transition |
| G10 | P2 | conceptual | `limited_scope_selected` dead end; scope never reaches packets | `decide`, `run_loop._allowed_scope` | scope only on the human record | scope surfaces in next packet's allowed scope |
| G11 | P2 | missing linkage | Agent evidence responses become new unlinked queue items | builder + ingest path | `verification_plan`/REQUEST_MORE_EVIDENCE, unlinked | optional linkage of agent-declared evidence to the gated action it answers (human confirms) |
| G12 | P2 | robustness | Approve is repeatable on an already-approved item | `available_human_actions` | second approval appends another record | idempotence guard or explicit "re-approve" affordance |

## 6. Proposed implementation slices (in order)

1. **Slice 1 — Human decision application / derived state (G1, G2, G3):**
   append-only `resolved_gates` records on the session (gate id(s), action_id,
   human_decision_id, scope, timestamp); approve on `plan_gate_resolution` →
   lifecycle `closed` (or a new terminal `resolved_by_human`); approve on a
   side-effecting action → `execution_status=admitted_not_executed` +
   lifecycle `ready_for_next_agent_instruction`; attention buckets and
   `needs_attention_count` exclude non-pending lifecycles. Never touches the
   original decision dicts.
2. **Slice 2 — Packet correctness (G1 follow-through):**
   `_open_gates_summary` = required_gates minus resolved gate ids, plus a new
   "HUMAN-RESOLVED GATES" packet section carrying scopes; `queue_summary`
   split by lifecycle (pending vs resolved).
3. **Slice 3 — Evidence accumulation fix (G4):** re-evaluate from the original
   envelope + all `evidence_records` for the action (fold in order); property:
   `missing_evidence` shrinks monotonically across supplies.
4. **Slice 4 — Bridge hygiene (G5):** `write_instruction` renames an existing
   `agent-response.md` to `agent-response.turn<N>.md`; ingest refuses a
   byte-identical already-ingested response unless explicitly overridden.
   Frame as ingestion hygiene, not an admission gate, to preserve the
   "bridge-state is never an admission authority" doctrine.
5. **Slice 5 — Gate-id plumbing (G6):** candidate carries the parsed
   `plan_gate` block metadata so Slice 1 can close the exact gates named.
6. **Slice 6 — Session resume parity (G8).**

**Recommended next slice: Slice 1.** It unblocks demo steps 6, 7 and 9
simultaneously and every later slice keys off its derived-state records.

## 7. Proposed tests (before/with implementation)

1. `test_approving_plan_gate_resolves_it` — approve a `plan_gate_resolution`
   item → lifecycle terminal, appended resolved-gate record, gone from
   `approval_needed`, absent from the next packet's open gates. (fails today)
2. `test_refused_item_leaves_attention_buckets` and
   `test_needs_attention_count_decreases_after_decisions`. (fails today)
3. `test_approved_side_effect_becomes_admitted_not_executed`. (fails today)
4. `test_evidence_accumulates_across_supplies` — missing_evidence shrinks
   monotonically; all-evidence-supplied end state pinned. (fails today)
5. `test_write_instruction_archives_previous_response` and
   `test_reingest_identical_response_is_refused_by_default`. (fails today)
6. `test_candidate_carries_plan_gate_closes_gates`. (fails today)
7. `test_blank_session_demo_end_to_end` — a pinned regression walk of the
   canonical scenario (the audit driver, essentially) asserting the coherent
   next-turn packet. (fails today)
8. Extraction-lab fixture additions: a second-turn response that closes a gate
   *and* proposes a follow-up action (mixed), and a duplicate-turn fixture
   for the bridge lab path.

No failing tests were added in this audit (they would all fail for the
documented reasons and be disruptive pre-implementation); the driver script
used for observation lives outside the repo in the session scratchpad.

## 8. Diagnostics run

| Check | Result |
|---|---|
| `git status` | clean at start; only the two report files added by this audit |
| `git log --oneline -10` | HEAD `75bc672` "fix: classify and label Cursor plan-gate responses" |
| `python -m pytest tests/ -k admissible -q` | **647 passed**, 1258 deselected, 154 subtests passed, 5.81s |
| Extraction lab (`python -m admissible.runner.extraction_lab …`) | **6/6 fixtures pass** (run without `--out`; no report files overwritten) |
| Control surface / run loop / cursor bridge tests | included in the `-k admissible` run (`test_admissible_control_surface`, `test_admissible_run_loop`, `test_admissible_cursor_bridge`) — all passing |
| Offline blank-session demo driver | executed; observations in §3 |

## 9. Verdict rationale

`DEMO_READY_WITH_SCRIPTED_LIMITS` was considered and rejected: scripting
cannot route around G1/G2 — the moment the human approves the plan gate on
camera, the surface visibly fails to acknowledge it (attention count frozen,
next packet contradicts the approval), and G4 makes the evidence lane
actively regress in front of the audience. Extraction and the bridge are not
the blockers. Hence **`NOT_DEMO_READY_P0_STATE_GAPS`**.
