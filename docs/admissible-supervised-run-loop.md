# Admissible Supervised Run Loop v0

## Purpose

The Control Surface (`docs/admissible-control-surface.md`) is a session
viewer: it can load a goal, run offline goal intake/plan audit, and load a
*static* trace of already-decided actions. It could not run a live,
turn-based loop with an external agent. The Supervised Run Loop closes that
gap: goal in -> a copyable "next agent instruction" packet out -> a human
pastes Cursor's/a frontier agent's response back in -> Admissible extracts
action candidates with the existing offline builder/evaluator -> gated
actions collect human decisions and evidence -> a follow-up instruction
packet is generated. This turns the Control Surface into a cockpit for a
manually-bridged, human-supervised agent loop.

## Product thesis (unchanged, extended)

- Cursor / a frontier agent **proposes** -- now including a raw text
  response the human pastes in by hand.
- Admissible **frames, audits, admits, limits, requests evidence, requests
  approval, refuses, and records decisions**. It still does not execute,
  and it still does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or
  any network provider -- the "bridge" between turns is entirely manual
  copy/paste by the human operator.
- The human/operator **decides**, and now can also **supply evidence** with
  a structured record instead of a free-text rationale on a generic
  decision form.

## Hard constraints (v0)

Same boundary as the base Control Surface, plus:

- The run loop never calls a model or network provider to produce the next
  instruction packet or to parse a pasted response -- both are deterministic,
  offline, rule-based functions (`admissible.run_loop`,
  `admissible.long_run_envelope_builder`, `admissible.evaluator.rules_only`).
- Ingesting a pasted agent response never executes anything; it only
  extracts action candidates and evaluates them with the existing rules-only
  evaluator.
- Evidence supplied by a human never mutates the original
  `RunEnvelope.decision` dict. A re-evaluation (when possible) produces a
  separate, linked `SupersedingAdmissionDecision`; the original is kept for
  audit.
- Autonomy level only changes the *wording* of what an agent may propose in
  the instruction packet (`may_propose`); the non-execution boundaries and
  "must not" list are identical, byte-for-byte, at every autonomy level.

## New data model (`admissible/run_loop.py`)

Additive only -- nothing in `admissible.control_surface` was removed or
renamed.

| Type | Purpose |
|---|---|
| `AgentInstructionPacket` | One turn's copyable "next instruction" packet: task, allowed scope, non-execution boundaries, what the agent may propose (autonomy-dependent), what it must not do, evidence still needed, open plan gates, queue summary, and the fully rendered `packet_text`. |
| `RunTurn` | One turn of the loop: the instruction packet issued and the response record that answered it (if any). |
| `AgentResponseRecord` | One raw, pasted response. Always `source_trust="unverified_agent_output"`. |
| `EvidenceRecord` | One piece of human-supplied evidence, linked to `action_id` / `decision_id` / `envelope_id`. |
| `SupersedingAdmissionDecision` | A new rules-only decision produced after evidence was folded in and the evaluator re-run. Linked to the evidence record and the previous decision id; never replaces the original decision object. |
| `RunLoopState` | All of the above for one session: `current_turn`, `turns`, `instruction_packets`, `response_records`, `evidence_records`, `superseding_decisions`. Stored on `ControlSession.run_loop` and round-trips through export/import like everything else. |

`RunEnvelope` (in `admissible.control_surface`) gained two optional,
additive fields: `envelope` (the full schema-shaped envelope, only present
for actions ingested via paste -- actions loaded from a static trace file
never have one) and `superseding_decisions` (a list, for audit).
`DecisionQueueItem` gained `lifecycle_status`.

## Human decision lifecycle statuses

Distinct from (and never a substitute for) the rules-only `decision` label:

- `needs_human_input` -- default for any gated decision.
- `evidence_supplied_pending_reevaluation` -- evidence was supplied but the
  action has no full envelope to safely re-run the evaluator against (the
  common case for actions loaded from a static trace file).
- `approval_supplied_pending_reevaluation` -- a scoped approval was recorded
  for a `REQUIRE_HUMAN_APPROVAL` action.
- `limited_scope_selected` -- a scope limit was recorded for an
  `ALLOW_WITH_LIMITS` action.
- `ready_for_next_agent_instruction` -- default for `ALLOW`, or the result
  of a successful evidence re-evaluation that resolved the gate.
- `closed` -- `REFUSE`, a recorded refusal, or an attested-executed `ALLOW`.

## Instruction packet contents

Deterministically built from goal intake, plan audit, autonomy level, and
the current queue (`admissible.run_loop.generate_instruction_packet`):

- **Task** -- from goal intake's task type + deliverable.
- **Allowed scope** -- local-workspace-only framing, the goal intake's
  non-execution boundary, and anticipated side-effect classes.
- **Non-execution boundaries** -- constant at every autonomy level (the
  hard-gate language the tests pin down).
- **What you may propose** -- autonomy-dependent wording (L0 analysis-only
  through L4 broadest-proposal-breadth); never authorizes execution.
- **What you must not do** -- deploy/install/delete without authorization,
  never treat autonomy or silence as approval for a gated action.
- **Evidence needed if continuing** -- aggregated from queue items still
  `needs_human_input` under `REQUEST_MORE_EVIDENCE`, plus an explicit note
  for items stuck at `evidence_supplied_pending_reevaluation`.
- **Open gates / unresolved plan items** -- plan audit verdict/gates and
  goal intake missing context/clarifying questions.
- **Continuation instruction** -- "propose and stop" wording for any
  blocked next step.

## Manual response ingestion

`ControlSurfaceController.ingest_agent_response(raw_text)`:

1. Wraps `admissible.long_run_envelope_builder.build_from_raw_output`
   (extraction) and `admissible.evaluator.rules_only.evaluate_envelope`
   (decision) unmodified -- the same pipeline used to build the sample
   trace (`admissible.long_run_truth`).
2. Stores the raw text as an `AgentResponseRecord`
   (`source_trust="unverified_agent_output"`).
3. Appends one `RunEnvelope` + `DecisionQueueItem` per extracted action
   candidate to the existing queue -- it never rewrites an existing item.

`build_from_raw_output`'s multi-action freeform extraction (see
"Multi-action freeform extraction (v0.3)" in
`docs/admissible-cursor-long-run-composition.md`) means a single pasted
response containing several proposed actions (e.g. an install, a push, and
a local edit) now surfaces all of them as separate queue items in one
`ingest_agent_response` call, each with its own `action_id` (prefixed
`resp_t<turn>_<index>_...`), decision, and missing-evidence set --
`admissible/runner/extraction_lab.py` is the regression harness that pins
this down against
`benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses/`.

## Evidence resolution loop

`ControlSurfaceController.provide_evidence(action_id, body)`, only valid for
a `REQUEST_MORE_EVIDENCE` item:

1. Records an `EvidenceRecord` linked to `action_id` / `decision_id` /
   `envelope_id`, `actor="human_operator"`.
2. If the action has a full envelope (ingested via paste), folds the
   evidence into a **copy** of `evidence.available`/`evidence.missing` and
   re-runs `evaluate_envelope` unmodified, producing a
   `SupersedingAdmissionDecision`. The queue item's *displayed* decision
   updates to the new result; the original `RunEnvelope.decision` is never
   touched.
3. Otherwise (no full envelope -- e.g. loaded from a static trace file),
   marks the item `evidence_supplied_pending_reevaluation` and leaves the
   decision untouched. This limitation is surfaced explicitly in the next
   instruction packet's "evidence needed" section.

## Architecture

```
admissible/run_loop.py                 packet generation, response ingestion, evidence re-evaluation (pure functions)
admissible/control_surface.py          ControlSession.run_loop + controller methods (generate/ingest/provide_evidence)
admissible/runner/control_surface.py   3 new POST routes
admissible/harness/control_surface.html   Run Loop panel + evidence form + categorized Needs Attention
```

## JSON API additions

| Method | Path | Effect |
|---|---|---|
| POST | `/api/session/run_loop/generate_instruction` | Generates and stores the next instruction packet; advances `current_turn`. |
| POST | `/api/session/run_loop/ingest_response` | `{"raw_response": "..."}` -> extracts + evaluates action candidates, appends to the queue. |
| POST | `/api/queue/{action_id}/evidence` | `{"evidence_type", "evidence_text", "file_path_or_note", "rationale"}` -> records evidence, re-evaluates if possible. |

## UI additions

- **Run Loop panel** (top of the page): current turn, "Generate next agent
  instruction" button, a read-only packet preview with a copy-to-clipboard
  button, a "Paste agent response" textarea, an "Ingest response" button,
  and a last-ingestion summary.
- **Selected Action panel**: a dedicated evidence form (type, evidence text,
  optional file path/note, rationale) for `REQUEST_MORE_EVIDENCE` items; the
  generic decision form now only shows the scope field for approve/
  limit_scope and the verification field for attest_executed, never all
  three at once.
- **Needs Attention panel**: five labeled buckets -- Evidence needed,
  Approval needed, Scope limits needed, Plan clarifications, Ready to
  continue -- instead of one flat list.

## What this is not

- Not an automatic bridge to Cursor/Claude Code/Codex/Gemini/OpenAI -- the
  human copies the packet out and pastes the response back in by hand.
- Not an executor -- ingestion only extracts and evaluates; nothing runs.
- Not a way to bypass `REFUSE` / `REQUIRE_HUMAN_APPROVAL` /
  `REQUEST_MORE_EVIDENCE` -- autonomy only changes proposal wording.
- Not a general-purpose re-evaluation engine -- evidence-triggered
  re-evaluation only applies to actions carrying a full envelope (i.e.
  ingested via paste in this session), and only ever adds a superseding
  decision, never mutates the original.
