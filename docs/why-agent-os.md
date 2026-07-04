# Why Agent OS

Agent OS exists because useful coding and research agents are still fallible — and normal prompts do not reliably preserve the structure that governed delegation requires.

## The epistemic problem

Large language models and agentic tools can draft code, search repositories, run commands, and produce plausible explanations. That utility is real. So is the failure mode: agents confabulate, overstate confidence, lose thread across long sessions, and treat a convincing answer as finished work.

When an owner delegates without durable structure, several things go wrong at once:

- **Mission drifts.** The original ask gets rewritten in the agent's own words. Scope expands or contracts without an explicit record.
- **Authority blurs.** It becomes unclear what the agent was allowed to do, what required approval, and what crossed an autonomy gate.
- **Evidence is implicit.** Claims live in chat scrollback instead of inspectable artifacts tied to a run.
- **Audit is informal.** "Looks good" replaces a recorded verdict against stated criteria.
- **Closure is ambiguous.** Work ends when the agent stops talking, not when the owner accepts an outcome under known constraints.

These are not tooling gaps in the sense of "missing a dashboard." They are **epistemic** gaps: the owner cannot reliably answer what was asked, what was permitted, what was done, what was verified, and what was accepted.

## What normal prompts do not preserve

A one-shot prompt or an open-ended chat thread is fine for small tasks. It is a poor container for governed delegation because it does not separate:

1. **Execution** — what the agent did or proposed
2. **Judgment** — what the owner permits, reviews, and accepts

Chat collapses these layers. The agent's output and the owner's decision share the same surface. Context mixes old missions with new ones. Evidence is whatever happened to be pasted last. There is no fail-closed gate that says "this run cannot close until required fields are filled."

Agent OS does not make agents correct. It makes the **delegation contract** explicit and inspectable on disk.

## Separation of execution and judgment

Agent OS structures a run as a set of markdown primitives under `.agent-os/` in a project that adopts the protocol:

| Concern | Primitive role |
|---------|------------------|
| What was asked | Mission and scope |
| What was permitted | Authority and autonomy gates |
| What was done | Evidence (registrar-only in v0) |
| What was verified | Audit verdict |
| What the owner accepts | Owner decision |
| How the run ends | Closure verdict |
| What persists | Memory update |

The CLI bootstraps workspaces, creates runs from templates, surfaces blocking fields, records audit verdicts, registers evidence, and attempts **fail-closed** closure. It does not execute agents, call LLMs, or substitute for owner review.

Execution stays with the agent (or the human doing the work). Judgment stays with the owner. The protocol is the membrane between them.

## The owner remains responsible

Agent OS is explicit about this: **the owner is not relieved of responsibility.** The protocol does not certify truth, guarantee quality, or auto-approve outcomes. It provides ceremony and structure so the owner can delegate more safely — not so delegation can run unsupervised.

Evidence helpers in v0 are **registrar-only**. They record what the owner or agent supplies; they do not execute commands, copy files, or judge whether evidence is sufficient. `evidence snapshot-git` is a narrow read-only exception with a fixed Git allowlist — not arbitrary shell access.

Audit and closure are recorded acts. Filling the fields is necessary for closure to succeed; it is not sufficient to make the work correct. The owner still decides what "pass" means and whether to accept the outcome.

## Closure is not truth

A closed run in Agent OS means: **required governance fields were present and closure validation passed.** That is a governed acceptance gate, not a proof that the agent was right.

Fail-closed closure is intentional. If mission, scope, authority, autonomy, evidence, audit, owner decision, or closure verdict is missing, the run stays open. The system prefers an honest "not ready" over a silent "done."

This distinction matters for teams and solo owners who need audit trails without pretending the tooling validated the substance of the work. Closure records that the owner followed the protocol to the point of acceptance — not that the universe agrees with the agent's output.

## Safer delegation, not more autonomy

The goal is not to maximize agent autonomy. It is to make delegation **governed**: bounded by mission, gated by authority, backed by evidence, reviewable in audit, and terminable only through owner decision.

More autonomy without structure increases risk. Agent OS trades some conversational convenience for inspectability. That trade is deliberate. v0 is meant for work where scope risk, reviewable artifacts, or handoffs matter — not for every trivial prompt.

## Why v0.1.0 is local and manual-first

The public `v0.1.0` release is an intentionally small surface:

- **Local filesystem protocol** — artifacts live in the adopting project's `.agent-os/`, not in a hosted service
- **Stdlib-only Python CLI** — install from source, no runtime dependencies
- **Manual-first** — the owner fills templates, registers evidence, records verdicts; nothing auto-runs or auto-closes
- **No cloud, UI, API, orchestration, or LLM calls** — by design, not as a missing feature

This scope keeps the epistemic model honest. A hosted "agent operating system" would invite assumptions about trust, multi-user authority, and automated judgment that v0 does not provide. Shipping a local prototype first forces clarity about what the protocol actually is: **structure for delegation**, not a runtime that executes or certifies agents.

Dogfood runs documented in `docs/` show the protocol on real tasks — from a small CLI change to a JSON config linter with a full evidence stack — without turning Agent OS into an executor. That is the intended shape for early adoption: try the loop locally, keep judgment human, close only when the record is complete.

## Summary

Agents are useful and fallible. Ungoverned delegation hides assumptions and blurs the line between doing and accepting. Agent OS separates execution from judgment, keeps the owner responsible, and treats closure as a governed gate — not as truth. Version 0.1.0 delivers that model as a local, manual-first filesystem protocol and CLI, without pretending to be a dashboard, orchestrator, or trust engine.

For the formal v0 boundary, see [`v0-release-boundary.md`](v0-release-boundary.md). For the product thesis, see [`thesis.md`](thesis.md).
