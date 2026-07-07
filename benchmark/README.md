# Admissible Benchmark

This directory contains Admissible benchmark artifacts: schemas, cases, gold annotations, prompts, scoring, and reports.

See `docs/Admissible_THESIS.md`, `docs/Admissible_ACTION_ENVELOPE.md`, and `docs/Admissible_BENCHMARK_SPEC.md` for the full specification this directory implements. See `docs/admissible-agent-os-lineage.md` for how Admissible relates to the Agent OS work elsewhere in this repository.

## Status

The benchmark directory now contains schemas, 25 Tier 1 enriched seed cases, gold annotations, a rules-only reference evaluator, a frontier-direct mock baseline runner, scoring, comparison and trace tooling, and a curated demo pack. This is a smoke-tested internal harness — **not a public benchmark result**. No empirical performance claims should be made from this seed set.

## One envelope, one action

One action envelope represents one proposed side-effecting action at the execution boundary. A multi-step agent plan must be split into one envelope per side-effecting step; this V0 schema layer does not model sequences (see BENCHMARK_SPEC.md Tier 4 for future sequence-benchmark scope).

## Object separation

- **`schemas/action_envelope.schema.json`** — the input. Describes a proposed action: actor, principal, request, proposed action, workflow context, evidence, policy context, authority context, risk context, provenance, and expected side effect.
- **`schemas/decision_output.schema.json`** — a system's output. What a frontier-model baseline or an Admissible evaluator returns after evaluating one envelope: a decision label, reasons, missing evidence, required approval, a safer next step, and an audit trace.
- **`schemas/gold_annotation.schema.json`** — the benchmark's ground truth. Stored separately from the envelope and never embedded in it: gold decision, gold risk level, gold failure modes if wrongly allowed, gold required evidence/approval, gold safer next step, and a per-label rubric.

The action envelope schema deliberately forbids `gold_decision`, `expected_decision`, `correct_label`, `rubric`, `score`, `baseline_result`, and `admissible_result` as top-level fields. Gold labels and rubrics belong only in the gold annotation schema. Mixing them into the envelope would leak the answer into the benchmark's input and contaminate every system evaluated against it.

## Leakage-sensitive fields

Some action envelope fields make a benchmark case easier by revealing part of the expected reasoning before a system has evaluated anything:

- `candidate_safer_next_steps` — may reveal the intended safer next step.
- `evidence.missing` — in a raw-tier envelope this should be used cautiously; listing exactly what's missing can hand a system the evidence dimension of the answer.
- `authority_context.required_approval` — when a benchmark case is testing whether a system can *infer* the required approval path, this field should be `"unknown"` rather than pre-filled.
- `policy_context.policy_gaps` — should only be listed when the absence of a policy is directly part of the scenario context, not inferred judgment.

Every benchmark case must report its `envelope_tier` (`raw`, `partially_enriched`, or `fully_enriched`) so results are never presented as evidence that a system can infer admissibility-relevant context from raw workflow data when it was actually given an enriched envelope.

## `envelope_tier` vs. benchmark tier — two distinct concepts

`envelope_tier` (a required field on every action envelope, values `raw` / `partially_enriched` / `fully_enriched`) describes **how enriched a single envelope's input fields are** — see "Leakage-sensitive fields" above.

This is distinct from **benchmark tier** (`tier_1_enriched` / `tier_2_partially_implicit` / `tier_3_adversarial` / `tier_4_sequence` per `docs/Admissible_BENCHMARK_SPEC.md`'s "Benchmark tiers" section), which describes **which difficulty class of case a benchmark case belongs to** (explicit/enriched mapping, partially implicit inference, adversarial robustness, or multi-step sequences).

Benchmark tier is currently represented only by directory structure (e.g. `benchmark/cases/tier_1_enriched/`) and is not yet a field on the envelope or gold annotation schema. Do not confuse the two: an envelope with `envelope_tier: fully_enriched` living under `cases/tier_1_enriched/` is the expected, consistent combination for this seed set — but the two values are independent axes, not synonyms.

## Examples

`examples/refund_email.envelope.json`, `examples/refund_email.decision.json`, and `examples/refund_email.gold.json` are schema-conformance examples only, adapted from the refund-email scenario in `docs/Admissible_ACTION_ENVELOPE.md`. They are not a benchmark case set and carry no empirical claim.

## Harness scope

The rules-only evaluator targets Tier 1 enriched cases. The frontier-direct baseline in the demo path uses mock plumbing, not a live frontier model. The seed set is small, hand-authored, and single-author annotated. See the top-level README "Non-claims" section for full claim boundaries.
