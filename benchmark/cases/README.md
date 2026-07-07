# Admissible Benchmark Cases

## Status

This directory contains the first **internal Tier 1 enriched seed cases** for Admissible. These are **not public benchmark results** and carry no empirical claim about any system's performance. They exist to test whether the schema, label distribution, and near-miss structure hold together before any runner or scoring harness is built.

## What is here

`tier_1_enriched/` contains 25 hand-authored action envelopes across 5 domains:

- `customer_communication/`
- `code_deployment/`
- `data_access/`
- `file_deletion/`
- `crm_record_mutation/`

Each domain has 5 cases covering all five decision labels (`ALLOW`, `ALLOW_WITH_LIMITS`, `REQUEST_MORE_EVIDENCE`, `REQUIRE_HUMAN_APPROVAL`, `REFUSE`) and belongs to one near-miss family (see below). Every envelope has `envelope_tier: fully_enriched` and `construction_mode: hand_authored_benchmark`, and validates against `benchmark/schemas/action_envelope.schema.json`.

Gold labels are stored **separately**, one line per case, in `benchmark/annotations/gold_labels.jsonl`, validating against `benchmark/schemas/gold_annotation.schema.json`. No envelope file contains a gold decision, rubric, or score.

## Purpose

This seed set is designed to test, in order:

1. that the action envelope and gold annotation schemas hold up against real (if hand-authored) content;
2. that a 5-domain, 5-label distribution is achievable without cartoonish cases;
3. that near-miss families genuinely flip the correct decision on small context changes rather than on action type alone;
4. that a future baseline runner, Admissible runner, and scoring harness will have something concrete to run against.

It is explicitly **not** designed to support any public claim about model or evaluator performance. See `docs/Admissible_BENCHMARK_SPEC.md`'s "Internal seed criteria" and "Public V0 acceptance criteria" for what would be required before any such claim.

## Near-miss families

Each domain forms one near-miss family (`metadata.near_miss_family_id`), where the same general action type recurs across all 5 cases but small changes in authority, evidence, policy, or approval flip the correct decision:

- `customer_refund_family` — draft vs. send, approval present vs. absent, requester legitimacy, evidence gap
- `production_deploy_family` — checklist vs. staging vs. production, rollback/approval presence, freeze-window policy, missing risk review
- `data_access_family` — aggregate vs. confidential export, unknown classification, prohibited destination, anonymized bounded export
- `file_deletion_family` — read-only listing, missing owner/backup evidence, known owner but no cross-team sign-off, archive vs. delete, audit-log prohibition
- `crm_mutation_family` — cited internal note, inference-only evidence gap, missing manager approval, hearsay-based change, staged proposal vs. applied change

Within each 5-case family, every pair of cases is a near-miss comparison, giving well over the minimum 10 near-miss pairs required for this slice across the full 25-case set.

## Tier 1 leakage rule

Tier 1 enriched cases are for schema and decision sanity checks. They are not sufficient for headline benchmark claims because enriched fields (`evidence.missing`, `policy_context.policy_gaps`, `authority_context.required_approval`, `risk_context.blast_radius`, `candidate_safer_next_steps`) can leak part of the reasoning target. Tier 2 partially implicit cases, which withhold these fields to test inference rather than mapping, will be needed before any serious claim is made.

## Annotation limitations

All gold labels in this seed were produced by a single annotator (`annotation_mode: single_author`, `adjudication_status: not_required`). Two cases (`customer_refund_unknown_requester_refused` and `crm_mark_churned_based_on_rumor_refused`) are flagged `ambiguous: true` because a defensible secondary label exists (`REQUEST_MORE_EVIDENCE`); the rubric explains why the primary label was chosen. A second-annotator review pass is required before this seed could support any public claim.
