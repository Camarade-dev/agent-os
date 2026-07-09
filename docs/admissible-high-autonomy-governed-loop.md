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

The controller, policy, transport, tests, and UI are in place for that live rehearsal
once Cursor is pointed at the workspace.

## Tests

`tests/test_admissible_high_autonomy_governed_loop.py` — deterministic four-turn flow with
`FixtureAgentTransport`.
