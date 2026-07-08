# Admissible Control Surface v0

## Purpose

The Truth Console (`admissible.harness.truth_console`) proves the trace
pipeline, but it is a static, read-only report generated once per run. The
Control Surface is the next layer: a local, interactive session UI that
feels closer to an LLM/agent interface while making Admissible's role as
the **governance layer** explicit -- goal intake, plan audit, an action
admission queue, and human decision controls, all backed by local JSON.

## Product thesis

- Cursor / a frontier agent **proposes**.
- Admissible **frames, audits, admits, limits, requests evidence, requests
  approval, refuses, and records decisions**. It does not execute.
- The human/operator **decides** when the current autonomy level calls for
  a decision.
- Agent OS remains historical lineage (see
  `docs/admissible-agent-os-lineage.md`), not a runtime dependency --
  `admissible/` and `benchmark/` never import `agent_os`
  (`tests/test_admissible_boundary.py` enforces this for every file under
  both trees, including everything added for this slice).

## Hard constraints (v0)

- Never calls Cursor, Claude Code, Codex, Gemini, OpenAI, or any network
  provider.
- Never executes shell commands from the UI or the server.
- Implements no automatic executor. "Attest executed" only **records**
  that an already-admitted local action was executed by a human/external
  actor -- it goes through the unmodified
  `admissible.admitted_execution.validate_executed_after_admission_record`
  validator (see `docs/admissible-admitted-execution-protocol.md`).
- Never weakens rules-only evaluator semantics
  (`admissible.evaluator.rules_only`) or admitted-execution validation.
- Never lets autonomy level override `REFUSE`, `REQUIRE_HUMAN_APPROVAL`, or
  `REQUEST_MORE_EVIDENCE` (see `docs/admissible-autonomy-levels.md`).
- A human decision never rewrites the original Admissible decision label;
  it is always a separate, linked `HumanDecisionRecord`.
- Generated session files live under `.admissible/` (already gitignored)
  and are never committed.

## Architecture

```
admissible/goal_intake.py        deterministic prompt -> GoalIntake
admissible/plan_audit.py         GoalIntake -> PlanCandidate, PlanCandidate -> PlanAudit
admissible/control_surface.py    ControlSession model + ControlSurfaceController
admissible/runner/control_surface.py   stdlib HTTP server + CLI ("--open")
admissible/harness/control_surface.html   self-contained HTML/CSS/JS UI
```

All decision logic lives in `admissible/control_surface.py`, which has no
HTTP dependency and is fully testable in isolation. The runner
(`admissible/runner/control_surface.py`) is a thin `http.server` adapter:
it parses requests, calls one `ControlSurfaceController` method, and
writes back JSON. It never shells out, never imports a provider SDK, and
never runs untrusted code from a request body.

## Running it

```powershell
python -m admissible.runner.control_surface --open
```

Starts a local server (default `http://127.0.0.1:8765/`), opens the
default browser, and serves the control surface. Session state is
persisted to `.admissible/control_surface_sessions/session.json` after
every mutation so the server can restart without losing state. Stop with
Ctrl+C.

Useful flags: `--host`, `--port` (`0` for an ephemeral port), `--open`,
`--session-dir`, `--sample-trace`.

## JSON API (same-origin only)

| Method | Path | Effect |
|---|---|---|
| GET | `/` | Serves the control surface HTML |
| GET | `/api/session` | Current session + derived UI fields (`state_view`) |
| GET | `/api/session/export` | Canonical session JSON (`session_dict`, round-trips with import) |
| POST | `/api/session/reset` | Start a fresh, empty session |
| POST | `/api/session/import` | Replace the session from an exported JSON body |
| POST | `/api/session/autonomy` | `{"level": "<AutonomyLevel>"}` |
| POST | `/api/session/goal` | `{"prompt": "..."}` -> goal intake + plan + plan audit |
| POST | `/api/session/load_sample` | Load the Slither sample goal + admitted-execution trace |
| POST | `/api/session/load_trace` | `{"path": "..."}` (optional; defaults to the sample trace, falling back to in-process builder-fixtures generation -- never a shell command -- if the file is missing) |
| POST | `/api/queue/{action_id}/decide` | `{"decision_type", "scope", "rationale", "verification"}` |

Every mutating endpoint returns the same `state_view()` shape the page
renders from, so the UI always reflects exactly what the server just did.

## UI panels

1. **Session transcript** (left) -- an LLM-chat-like log: user prompts,
   goal intake summaries, plan proposals, plan audits, and Admissible
   messages, in order.
2. **Top controls** -- autonomy level selector, "Load sample Slither
   session", "Export session JSON", "Import session JSON", "Reset local
   session".
3. **Goal Intake panel** -- task type, deliverable, project maturity,
   complexity, global risk, architecture-choice burden, missing context,
   recommended autonomy ceiling, clarifying questions.
4. **Plan & Independent Plan Audit panel** -- the generated plan steps
   (with gates) and the separately computed audit verdict, reasons, and
   required gates.
5. **Admissible Action Admission Queue** -- one card per loaded action:
   id, tool/command, Admissible decision, operational action, execution
   status, missing evidence/approval gaps, and a decision form scoped to
   exactly the human actions that decision label permits.
6. **Decision Records panel** -- every `HumanDecisionRecord` made in the
   UI, linked back to its decision/envelope id.

## Sample data

"Load sample Slither session" loads the same prompt used to build
`benchmark/reports/admissible_cursor_admitted_execution_truth_console_trace.json`
(see `docs/admissible-admitted-execution-protocol.md` and
`docs/admissible-cursor-long-run-composition.md`) and its 31 admitted
actions. If that trace file is missing, the controller falls back to
building one **in-process** from
`benchmark/long_run_scenarios/cursor_slither_demo/fixtures` via
`admissible.long_run_truth.build_truth_trace_from_raw_output_fixtures` --
a direct Python function call, never a subprocess or shell command.

## What this is not

- Not an executor, not a terminal, not a way to run commands from the
  browser.
- Not a provider client of any kind.
- Not a replacement for `admissible.evaluator.rules_only` -- the queue
  only ever displays decisions that evaluator already produced.
- Not a way to bypass `REFUSE` / `REQUIRE_HUMAN_APPROVAL` /
  `REQUEST_MORE_EVIDENCE` -- see `docs/admissible-autonomy-levels.md`.

## Module entry points

- `admissible.goal_intake.analyze_goal`
- `admissible.plan_audit.generate_plan_candidate`, `admissible.plan_audit.audit_plan`
- `admissible.control_surface.ControlSurfaceController`
- `admissible.control_surface.available_human_actions`

CLI:

```powershell
python -m admissible.runner.control_surface --open
```
