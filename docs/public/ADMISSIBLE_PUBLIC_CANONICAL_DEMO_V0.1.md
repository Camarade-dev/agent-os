# Admissible — Governed Execution, Evidence-Backed Results

## The model proposes. Admissible authorizes.

An agent's completion message is a claim, not the authoritative result.

Admissible captures execution evidence, reconstructs the result independently, refuses unsupported completion claims, and presents evidence-backed accepted results.

The point is not simply whether an agent says it finished. The point is whether the evidence supports accepting the result.

## Evidence class 1 — Documented incident replay

The project documentation describes the same user intent across two repair attempts.

The agent claims completion in both attempts. The first run is refused because replay behavior is inconsistent with the required behavior. The corrected run is accepted only after the required behavior and the independently reconstructed evidence agree.

Provider-free tests reproduce these authority outcomes with deterministic fixtures. They are deliberately not presented as reproductions of a real provider execution.

This is a documented refusal-to-corrected-acceptance workflow. It is not presented as a matched live refusal-to-authorization pair with raw receipts for both attempts.

## Evidence class 2 — Separate historical live run

A separate archived run, `neon-serpents-live-002`, is classified in the repository as real live-run evidence rather than a test fixture.

Its frozen summary records:

- 8 admitted operations;
- 8 physical writes;
- 8 durable receipts;
- 8 FileEvidence records;
- structural verification passed;
- final phase `awaiting_human`.

This live run is a different workload from the documented incident replay. It is included as separate execution evidence, not as the accepted half of that replay.

## What this demonstrates

This public demo supports a narrow set of claims:

- an agent completion message is not automatically the authoritative result;
- documented replay evidence can cause a claimed completion to be refused;
- a corrected attempt is separately evaluated before acceptance;
- the project contains a historical live run with persisted physical-write and durable-receipt evidence.

## What this does not claim

This demo does not claim:

- universal safety;
- production readiness;
- benchmark superiority;
- research novelty.

It also does not claim that the documented replay is a matched live refusal-to-authorization pair.

The evidence classes remain separate on purpose.
