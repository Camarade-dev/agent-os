# Admissible Blocker / Recovery Loop Demo

Slice `ADMISSIBLE_DEMO_024_BLOCKER_AND_RECOVERY_LOOP`.

## What this demo proves

The two-turn local build demo (`ADMISSIBLE_DEMO_023`) showed a happy path:
goal → propose → admit → execute → evidence → continue → repeat.

This slice adds a **deterministic blocker/recovery sequence** on top of that
flow. It proves that a governed run can continue safely when an agent proposes
inadmissible or not-yet-authorized actions:

```
Turns 1–2: happy-path scaffold + enhancement (same as demo 023)
Turn 3:    agent proposes npm install + deploy -> gated, not executed
           continuation carries blocked proposals as not completed
Turn 4:    agent proposes revised local-only file writes -> admitted,
           explicitly executed, evidence accumulates, run continues
```

Nothing auto-executes. Nothing calls a provider. Nothing runs shell, npm,
network, or deploy.

## How it differs from the happy-path multi-turn demo

| Aspect | Demo 023 (two-turn) | Demo 024 (blocker/recovery) |
|--------|---------------------|-----------------------------|
| Agent mistakes | None — every proposal is local `write_file` | Turn 3 proposes forbidden ops |
| Ingest side effects | Never writes files (both demos) | Turn 3 ingest also writes no files |
| Admission | All proposals `ALLOW` | Turn 3: `REQUEST_MORE_EVIDENCE` + `REQUIRE_HUMAN_APPROVAL` |
| Local batch execution | Every admitted turn executes | Turn 3 ops never appear in `ready_to_execute_locally` |
| Continuation | Grounded in executed evidence | Also lists Turn 3 ops as **not completed** |
| Recovery | N/A | Turn 4 fixture proposes admissible local alternative |

## Forbidden actions used (Turn 3 fixture)

`tests/fixtures/admissible/tiny_game_turn_3_blocked_agent_response.md` proposes:

| Proposal | Extracted as | Admission decision | Why |
|----------|--------------|-------------------|-----|
| `npm install --save-dev vite` | `install_dependency` | `REQUEST_MORE_EVIDENCE` | Dependency install needs package trust / license / lockfile review |
| `deploy to production` | `deploy_code` | `REQUIRE_HUMAN_APPROVAL` | Production deploy needs explicit human approval |

These use the existing freeform extraction patterns in
`admissible.long_run_envelope_builder` (`Proposed command:` / `Proposed deployment:`)
and the rules-only evaluator — no new operation types were invented.

## How Admissible prevents execution

1. **Ingest is record-only** — parsing and admission never touch the workspace.
2. **Admission gates** — `install_dependency` and `deploy_code` do not receive
   `ALLOW`; they stay at `proposed_only` execution status.
3. **Bounded executor eligibility** — neither action has structured local file
   operations, so they never appear in `ready_to_execute_locally`.
4. **Explicit batch execution** — even if an operator clicks execute, only
   admitted local structured ops run; forbidden action types are excluded.

## How continuation carries the blocker forward

After Turn 3 ingest (with Turns 1–2 already executed), continuation is
**available** because there are no pending admitted local ops from Turn 3.

`build_continuation_instruction(...)` includes Turn 3 action ids under:

```
ACTIONS BLOCKED / REFUSED / NOT EXECUTED (must NOT be treated as done)
```

Each blocked proposal is categorized as `awaiting_human_decision` with the
existing missing-evidence or approval-required reason. The instruction also
restates bridge constraints (`Do not use shell, npm, network, or deploy commands`)
and asks for the next smallest admissible local-only step.

This is **supervised continuation**, not autonomous recovery: Admissible does
not rewrite the agent's proposal or auto-retry. Turn 4 is a separate fixture
(human/agent paste) that deliberately proposes a local-only alternative.

## Recovery scenario (Turn 4 fixture)

`tests/fixtures/admissible/tiny_game_turn_4_recovery_agent_response.md` proposes:

- `LOCAL_DEV.md` — documents that the game is local-only with no package manager,
  bundler, external scripts, or publishing step
- `index.html` — adds a visible on-screen local-only banner

Both are `write_file` structured operations, admitted as `ALLOW`, executed via
explicit bounded local batch, and attested with sha256 evidence (8 total records
after four turns).

## Fixtures

| File | Role |
|------|------|
| `tests/fixtures/admissible/tiny_game_turn_1_agent_response.md` | Turn 1 scaffold (reused from demo 023) |
| `tests/fixtures/admissible/tiny_game_turn_2_agent_response.md` | Turn 2 enhancement (reused from demo 023) |
| `tests/fixtures/admissible/tiny_game_turn_3_blocked_agent_response.md` | Turn 3 blocker (`npm install` + deploy) |
| `tests/fixtures/admissible/tiny_game_turn_4_recovery_agent_response.md` | Turn 4 local-only recovery writes |

## How to replay

### Automated (recommended)

```bash
python -m pytest tests/test_admissible_blocker_recovery_loop_demo.py -q
```

Regression with the two-turn demo and related suites:

```bash
python -m pytest tests/test_admissible_multi_turn_local_build_demo.py tests/test_admissible_blocker_recovery_loop_demo.py tests/test_admissible_evidence_grounded_continuation.py tests/test_admissible_run_timeline.py -q
```

Full Admissible subset:

```bash
python -m pytest tests/ -k admissible -q
```

### Manual Control Surface walkthrough (optional)

1. Complete Turns 1–2 as described in `docs/admissible-multi-turn-local-build-demo.md`.
2. Generate turn 3 instruction, paste `tiny_game_turn_3_blocked_agent_response.md`.
3. Confirm no new workspace files; inspect **Run Timeline** turn 3 ops (not executed).
4. Open **Evidence-Grounded Continuation** — blocked ops appear under not completed.
5. Generate turn 4 instruction, paste `tiny_game_turn_4_recovery_agent_response.md`,
   execute the bounded local batch, confirm `LOCAL_DEV.md` and evidence count increase.

## Remaining gaps before bounded verification / final live demo

- Autonomous repair is intentionally out of scope — recovery remains fixture-driven.
- `REFUSE`-tier actions (policy conflict) are not exercised here; Turn 3 uses
  evidence/approval gates instead.
- No partial batch failure recovery (e.g. one of two writes fails mid-batch).
- Bridge does not yet auto-write the evidence-grounded continuation text.
- No post-recovery bounded verification (browser smoke test) for the game.
- Live Cursor rehearsal with real model proposals (vs deterministic fixtures).

## Tests

`tests/test_admissible_blocker_recovery_loop_demo.py` covers fixture parsing,
the full four-turn controller flow, ingest gates on Turn 3, continuation
not-completed projection, Turn 4 admission/execution/evidence, timeline turn
separation across four turns, and forbidden-capability absence.
