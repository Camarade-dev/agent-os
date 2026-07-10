# Admissible High-Autonomy Governed Loop (v0)

Slice: `ADMISSIBLE_RUN_029_HIGH_AUTONOMY_GOVERNED_LOOP_V0`

## Why this slice exists

Previous Admissible slices built every *piece* of a governed run — goal intake, admission,
bounded local execution, evidence-grounded continuation, blocker/recovery demos, and the
Cursor file bridge — but the **human was still the driver**. Operators had to copy
continuation text, click ingest, click execute batch, and advance each turn by hand.

This slice introduces the first **tick-driven high-autonomy controller**: the user submits
one goal, starts a high-autonomy run, and Admissible drives the loop through safe,
explicit steps.

This is the real long-running loop substrate — not another operator runbook.

## What is automated

When high-autonomy mode is **explicitly started** (opt-in, L4 autonomy):

1. **Instruction dispatch** — writes the next instruction (first-turn packet or
   evidence-grounded continuation) to the agent bridge via `AgentTransport`.
2. **Response detection** — polls the bridge for a new `agent-response.md` (or fixture
   transport in tests).
3. **Ingest** — calls the existing `ingest_agent_response` path (no direct file writes
   on ingest).
4. **Admission** — unchanged rules-only evaluator; gates are not weakened.
5. **Auto-execution** — admitted `ALLOW` local file operations inside the configured
   workspace are executed through the existing bounded executor, with sha256 evidence.
6. **Recovery** — npm/deploy/shell blockers trigger an automatic local-only recovery
   instruction; blocked actions remain **not completed**.
7. **Verification** — bounded verification runs as an explicit controller step when policy
   says it is safe (after pending local writes are done and no next instruction is due).
8. **Stop** — when verification has run and no further agent responses are expected.

Each step is one `tick_high_autonomy_run` call — no hidden background process.

## What still requires human approval

High-autonomy **never** auto-approves:

| Category | Examples |
|----------|----------|
| `REQUIRE_HUMAN_APPROVAL` (non-recoverable) | Shell commands, secrets/env access |
| Deploy / publish | Production deploy proposals |
| Dependency install | `npm install`, `pip install`, etc. |
| Network / external access | curl, CDN fetches, provider calls |
| Writes outside workspace | Path escape, absolute paths |
| Destructive / irreversible | Deletes, git push, chmod |
| Arbitrary shell | Any command execution |
| Explicit `REQUIRE_HUMAN_APPROVAL` decisions | Cannot be overridden by autonomy level |

**Recoverable blockers** (demo: npm + deploy on turn 3) do **not** pause the run; the
controller writes a recovery instruction asking for a local-only alternative. Those
actions stay on the queue as **not completed**.

## Policy: auto-execution vs pause

`HighAutonomyPolicy` classifies each queue item:

- **auto_executable** — admitted `ALLOW`, structured local op, inside workspace, supported
  by bounded executor, passes content guards.
- **recoverable_blocker** — `install_dependency`, `deploy_code`, etc. with
  `REQUEST_MORE_EVIDENCE` / `REQUIRE_HUMAN_APPROVAL`; recovery continuation is issued.
- **human_critical** — shell, secrets, outside workspace, non-recoverable approval; run
  enters `human_required` and waits for Approve / Refuse.
- **blocked_not_completed** — refused or ineligible; never executed.

Auto-execution is capped per turn (`DEFAULT_MAX_AUTO_EXECUTIONS_PER_TURN = 8`).

## Transport boundary (`AgentTransport`)

```text
write_instruction(text)
read_response_if_changed() -> (text, cursor)
response_cursor
clear_or_archive_response()
```

Implementations:

- **`FileBridgeAgentTransport`** — production path; writes
  `.admissible/next-agent-instruction.md`, reads `.admissible/agent-response.md`.
  Does **not** call Cursor APIs.
- **`FixtureAgentTransport`** — deterministic test transport with scripted responses.

v0 does not fake Cursor integration: Cursor must run externally and write the response
file. Admissible removes manual copy/paste of continuation text.

## Controller API

| Method / route | Purpose |
|----------------|---------|
| `start_high_autonomy_run` | Opt in; set L4; bind workspace + transport |
| `pause_high_autonomy_run` | Operator pause |
| `resume_high_autonomy_run` | Resume paused run |
| `stop_high_autonomy_run` | Stop with reason |
| `tick_high_autonomy_run` | Advance at most one safe step |

HTTP: `/api/session/high_autonomy/{start,pause,resume,stop,tick,approve,refuse}`

## UI

A top-level **High-Autonomy Governed Run** panel shows only:

1. What is being done now
2. What is needed now
3. What is blocking
4. Last meaningful event
5. Evidence / verification summary
6. One primary button (Start / Pause / Resume / Stop / Approve / Refuse)

Manual bridge, queue, timeline, and transcript are under **Advanced / Debug**.

## Human-critical refusal recovery

When a turn proposes genuinely human-critical actions (e.g. `git push`, `git commit`,
`publish`, a shell command, or a write outside the workspace), the loop pauses in
`mode = human_required` and stops the browser auto-run. The state now describes the pause
**per action**, not with a single generic message:

- `human_required_action_ids` / `human_required_action_count` — every currently-open
  human-critical action still awaiting a decision.
- `human_required_actions` — concise `{action_id, action_type, tool_or_command, reason}`
  labels the panel lists so the operator sees exactly what is blocking.

An action only counts as an open human-critical blocker when a human decision is actually
available for it. A capability the rules-only evaluator already `REFUSE`d is
human-critical by capability but offers no human action — it is already blocked and never
pins the loop in `human_required`.

### What happens after **Refuse**

`refuse_high_autonomy_human_action` (route `/api/session/high_autonomy/refuse`):

1. Records a refusal decision — through the existing `decide()` / `HumanDecisionRecord`
   model — against **every** currently-open human-critical action, not just the surfaced
   one. (Refusing only one used to leave the others open, re-entering `human_required` on
   the next tick — the stuck-UI bug this fixes.)
2. Marks those actions refused/closed and **not completed** (`lifecycle = refused_closed`,
   `execution_status` stays `proposed_only` — never executed).
3. Does **not** re-ingest the already-consumed response; stale/duplicate-response
   protection stays intact and a recorded "duplicate response" bridge warning is
   non-fatal.
4. Leaves `human_required` and sets `mode = recovering`, `next_action =
   write_recovery_instruction`.
5. On the next safe tick, composes a **bounded local-only** recovery instruction grounded
   in the refused actions: it names them, says they are not completed and must not be
   retried in their forbidden form, and asks for the next smallest admissible local-only
   structured operation writing only `.admissible/agent-response.md` — no shell, npm, pip,
   git push/commit, publish, deploy, network, CDN, secrets, or paths outside the
   workspace. It is written to `.admissible/next-agent-instruction.md`; `mode` becomes
   `waiting_for_agent` and auto-run may safely continue.

### Why **Approve** does not create forbidden executor powers

`approve_high_autonomy_human_action` records approval/admission **intent only** for the
one targeted action. v0 has no automatic shell/network/deploy executor at any level, so an
approved human-critical action is marked `admitted_not_executed` — a human still runs it
externally. Approval is a deliberate per-action authority grant, so it targets a single
action; a non-approvable proposal (e.g. `REQUEST_MORE_EVIDENCE`) is rejected with a clear
error rather than inventing approval authority. If other human-critical actions remain, the
loop stays in `human_required` for them.

## Manual mode unchanged

Supervised mode is the default. Without calling `start_high_autonomy_run`, behavior is
identical to prior slices: ingest never executes; batch execute remains explicit.

## What this is not

- Not provider integration (no Cursor/OpenAI/Gemini API calls)
- Not arbitrary shell execution
- Not npm / deploy / network execution
- Not weakened admission or content guards
- Not default-on autonomy

## Preparing the final demo

This slice proves the four-turn blocker/recovery demo can run **without a human driver**
using fixture transport. Remaining gap for a true live Cursor high-autonomy run:

1. **External Cursor** must read the instruction file and write the response file each turn.
2. **File bridge polling** in production uses mtime/sha256 on `agent-response.md`.
3. **Turn latency** is human/agent-bound; the browser may call `tick` on an interval while
   `mode === waiting_for_agent`.
4. **Human-critical pauses** need the operator to Approve/Refuse in the minimal panel.
   Refuse always clears every open human-critical action and hands off a local-only
   recovery instruction (see *Human-critical refusal recovery*), so the run continues
   safely without re-entering `human_required`.

The controller, policy, transport, tests, and UI are in place for that live rehearsal
once Cursor is pointed at the workspace.

## Update — model-agnostic agent transport (slice ADMISSIBLE_RUN_032)

The `AgentTransport` above is the **pull / external** shape: write an instruction, then poll
for a response file that a human-driven editor produces. That is semi-autonomous. A later
slice adds a **model-agnostic `AgentBackend`** callable shape so the same tick loop can
*invoke* an agent backend directly (Cursor CLI first; fixture backend in tests), with the
agent confined to an isolated agent workspace and no direct write authority over the target
workspace. See [the model-agnostic agent transport doc](admissible-model-agnostic-agent-transport.md).

The auto-execution described here is unchanged, but the truthful framing is: Admissible has
**no arbitrary executor** and runs no shell/npm/network/deploy — **only admitted low-risk
local writes may be auto-executed** in high-autonomy mode, and **human-critical actions still
stop**.

## Tests

- `tests/test_admissible_high_autonomy_governed_loop.py` — deterministic four-turn flow
  with `FixtureAgentTransport`.
- `tests/test_admissible_live_high_autonomy_hardening.py` — live file-bridge hardening and
  the human-critical pause path.
- `tests/test_admissible_high_autonomy_human_required_recovery.py` — human-critical refusal
  recovery: refusal clears all open actions, exits `human_required`, writes a local-only
  recovery instruction, and approval records intent without inventing an executor.
- `tests/test_admissible_model_agnostic_agent_transport.py` — the callable `AgentBackend`
  shape, workspace safety, and Cursor CLI configuration.
- `tests/test_admissible_cursor_agent_windows_environment.py` — Windows-safe subprocess env
  builder and probe parity (slice ADMISSIBLE_RUN_036).
- `tests/test_admissible_callable_terminal_pause.py` — terminal callable-backend pause,
  exactly-once/no-rebilling, and disjoint file-bridge vs callable UI wording
  (slice ADMISSIBLE_RUN_036).

## Run 038 closure and governance contract

`ADMISSIBLE_RUN_038_LIVE_RUN_EFFICIENCY_CLOSURE_AND_GOVERNANCE_HARDENING` makes
`pixel-wanderer-cli-006` the canonical long-run regression without claiming that the
source run completed. The governed loop now uses these durable rules:

- The agent proposes the next smallest **coherent bounded batch**, not the smallest
  individual operation. The default response bound is eight structured operations and
  256 KiB of proposed UTF-8 write content. Every path remains workspace-relative and the
  bounded executor still rejects shell, package-manager, network, deploy, destructive,
  external-resource, executable-command, and secret-reference content.
- Every continuation carries a concise current-state progress ledger: acceptance criteria,
  satisfied/open criteria, latest final file hashes, pending useful operations,
  stale/superseded actions, remaining work budget, closure phase, and batch limits. It does
  not replay the historical transcript.
- Canonical fingerprints are `write_file + normalized path + sha256(content)`,
  `read_file + normalized path + observed/expected sha256`, and `list_files + normalized
  path`. Repeated executed work closes as `duplicate_noop`; a write already matching disk
  closes as `already_satisfied_noop`.
- Safe overwrite remains low-risk only for a non-sensitive path under the submitted goal
  when this run created the file and current disk sha256 matches latest execution evidence.
  A pre-run file, changed sha256, sensitive/executable path, ambiguous scope, destructive
  operation, external resource, secret, or authority escalation requires human review or
  stronger evidence.
- Model text is never admission authority. A “Human decision required” sentence that merely
  restates approval for a separately extracted `ALLOW` operation is suppressed. Equivalent
  gates merge, and already-covered gates are superseded with `superseded_by_action_id`,
  reason, and timestamp. Supersession is queue cleanup, not approval.
- Only open, non-superseded, genuinely human-critical actions pause the loop. `REFUSE`,
  `REQUEST_MORE_EVIDENCE`, sensitive overwrite, destructive/irreversible work, external
  authority, and actual unresolved user choices retain their hard gates.

### Acceptance, verification, and outcomes

Each high-autonomy run persists criteria with `criterion_id`, source text, mandatory flag,
status (`open`, `evidence_available`, `verified_pass`, `verified_fail`, `waived`), evidence
references, verification notes, and generic allowlisted verification requests. A model may
emit `ADMISSIBLE_COMPLETION_CANDIDATE`, but the record is advisory and cannot waive or
self-authorize a criterion.

A run reaches `completed` only when all mandatory criteria are `verified_pass` or explicitly
human-waived, deterministic verification is final, no active human-critical blocker remains,
and no useful admitted operation is pending. Other final states are `incomplete`, `failed`,
`stopped_by_budget`, and `stopped_by_operator`, each with an exact reason and unmet/pending
state.

The model-invocation budget is split into work and closure capacity. With the default 12-turn
budget and two-turn closure reserve, turn 10 enters completion-first mode. Pending response
ingest, admitted bounded execution, and deterministic local verification finish even at the
turn boundary because they require no additional model call. Budget exhaustion is reported
as `stopped_by_budget`, never generic “Stopped”.

Canonical metrics separate backend invocation/retry/empty-success usage; useful writes,
unique file states, duplicate no-ops, and overwrites; reads/lists; verification checks; genuine
human interventions, suppressed pseudo-gates, superseded gates, and active blockers; and
work/verification/closure budget usage. `active_blocked_count` is the one definition used by
the persisted run, export, summary, governed overview, and UI.

## Run 040 verification repair, pseudo-gates, and portable export

`ADMISSIBLE_RUN_040_VERIFICATION_REPAIR_CLOSURE_PSEUDO_GATE_AND_EXPORT_FIX` closes the
`pixel-wanderer-cli-010` regression without broadening executor authority.

- **Proposal coverage:** after extraction, compare mandatory goal paths against proposed and
  already-satisfied paths. Safe partial batches may execute; missing mandatory paths trigger
  `repair_needed` rather than rejecting the whole batch. README does not satisfy LOCAL_DEV.md.
- **Repair-needed state machine:** `verification_failed_repairable → repair_needed →
  writing_repair_instruction → awaiting_repair_response → repair_executing → repair_verifying`.
  Repair packets contain only failed mandatory criteria, diagnostics, satisfied hashes, exact
  missing paths, boundaries, and remaining budget. Default `max_repair_rounds=2`.
- **Verification fail ≠ internal mismatch:** ordinary failed acceptance criteria must not become
  `internal_livelock`. Livelock is reserved for contradictory execution state.
- **Aggregate pseudo-gate suppression:** prose such as “Approve bounded execution of the four
  structured write_file operations below” is suppressed when concrete sibling operations exist.
  Stale persisted gates are repaired on session load. Metrics distinguish
  `raw_human_decision_count`, `genuine_human_intervention_count`, and
  `retrospectively_suppressed_pseudo_gate_decision_count`.
- **Non-null projections:** `outcome` defaults to `in_progress`; counts default to `0`;
  `blocking_reason` defaults to empty string. Legacy null session fields migrate on load/export.
- **Portable JSON:** environment diagnostic keys are canonicalized case-insensitively before
  export; source aliases are recorded separately, never as duplicate object keys.
