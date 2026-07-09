# Admissible Multi-Turn Local Build Demo

Slice `ADMISSIBLE_DEMO_023_MULTI_TURN_LOCAL_BUILD`.

## What this demo proves

This is the first **concrete two-turn governed local build loop** in repo tests.
It exercises the full supervised chain twice, using deterministic fixtures only:

```
goal
  -> turn 1 instruction
  -> agent proposal (fixture)
  -> admission (no writes on ingest)
  -> explicit batch execution
  -> sha256 evidence
  -> evidence-grounded continuation
  -> turn 2 instruction
  -> agent proposal (fixture)
  -> admission
  -> explicit batch execution
  -> accumulated evidence
  -> run timeline (both turns)
```

The scenario is a tiny browser game (`index.html`, `style.css`, `game.js`):

| Turn | Agent proposes | After explicit execution |
|------|----------------|--------------------------|
| 1 | Scaffold the three game files | Files exist; evidence attests each write |
| 2 | Score + restart + WASD controls; add `README.md` | Enhancements applied; six total evidence records |

Nothing auto-executes. Nothing calls a provider. Nothing runs shell, npm, network,
or deploy.

## Fixtures

Deterministic agent responses (structured-operation contract):

| File | Role |
|------|------|
| `tests/fixtures/admissible/tiny_game_turn_1_agent_response.md` | Turn 1 scaffold (3× `write_file`) |
| `tests/fixtures/admissible/tiny_game_turn_2_agent_response.md` | Turn 2 enhancement (3× `write_file`) |

Each block uses the `ADMISSIBLE_STRUCTURED_OPERATION:` marker and fenced JSON
payloads compatible with `extract_structured_operation_blocks` and the bounded
local executor.

An older single-turn scaffold also lives at
`benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses/tiny_local_game_structured_scaffold.txt`.
The multi-turn demo fixtures are aligned with that content for Turn 1 and extend
it for Turn 2.

## How to replay

### Automated (recommended)

```bash
python -m pytest tests/test_admissible_multi_turn_local_build_demo.py -q
```

Related regression suites (timeline, continuation, batch execution):

```bash
python -m pytest tests/test_admissible_run_timeline.py tests/test_admissible_evidence_grounded_continuation.py tests/test_admissible_execution_review_ux.py -q
```

Full Admissible subset:

```bash
python -m pytest tests/ -k admissible -q
```

### Manual Control Surface walkthrough (optional)

1. Start the Control Surface: `python -m admissible.runner.control_surface --open`
2. Submit the canonical tiny-game goal.
3. Paste contents of `tiny_game_turn_1_agent_response.md` into agent response ingest.
4. Confirm no files appear in the workspace until you click **Execute bounded local batch**.
5. Open **Evidence-Grounded Continuation** — it becomes available after execution
   and lists Turn 1 paths + sha256 values.
6. Generate the next instruction (turn 2), paste `tiny_game_turn_2_agent_response.md`,
   execute the second batch, and inspect the **Run Timeline** panel.

This manual path mirrors live Cursor use later; the tests do not depend on Cursor.

## Why this is still not full autonomy

- **Human-triggered execution** at every batch step.
- **Human-triggered ingest** for each agent response.
- **No completion model** — continuation always asks for the next smallest
  admissible step; it never declares the goal done.
- **No blocker/recovery loop** yet — if execution fails or the agent proposes
  forbidden actions, recovery is manual.
- **No bounded verification** pass after Turn 2 (e.g. automated smoke test of
  the game in a browser).
- The Cursor bridge still writes the standard instruction packet via
  `generate_next_instruction_packet`; copying the evidence-grounded continuation
  text remains a human step until a later slice wires that path.

## Preparing for live Cursor multi-turn demo

This slice makes the two-turn loop **reproducible offline**. The same fixtures
can be pasted into `.admissible/agent-response.md` during a live bridge session.
The governed invariants hold:

- ingest never writes files;
- admitted ops wait for explicit execution;
- continuation blocks until execution evidence exists;
- timeline and evidence accumulate across turns.

## Remaining before `ADMISSIBLE_DEMO_024_BLOCKER_AND_RECOVERY_LOOP`

- Blocker detection and bounded recovery when batch execution partially fails.
- Explicit handling when Turn 2 proposes forbidden ops alongside local writes.
- Optional wiring: bridge writes evidence-grounded continuation text instead of
  (or in addition to) the generic next packet.
- Completion / verification model for declaring the demo goal satisfied.
- Inter-turn diff in continuation ("what changed since last turn").

## Tests

`tests/test_admissible_multi_turn_local_build_demo.py` covers fixture parsing and
the full two-turn controller flow: ingest gates, batch execution, sha256
evidence, continuation grounding, timeline turn separation, forbidden-capability
absence, and the no-completion-signal boundary.
