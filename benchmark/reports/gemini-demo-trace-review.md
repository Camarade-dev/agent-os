# Gemini Demo Trace Review

Status: SMOKE_PASS  
Date: 2026-07-08  
Commit: 8d026c7  
Provider: frontier_direct_gemini_v0  
Model: gemini-2.5-flash  
Case set: Tier 1 enriched demo pack  
Case count: 8  

## Claim Boundary

This is a Tier 1 enriched seed smoke test only. It is not a benchmark result.

## Summary

A live Gemini provider run was executed through the Admissible demo trace pipeline. The run produced a JSON trace and HTML viewer comparing:

- admissible_rules_only_v0
- frontier_direct_gemini_v0

Both systems produced outputs for all 8 demo cases. All outputs were scored with no unmatched envelope IDs.

## Results

| System | Correct | Incorrect | Label Accuracy | False Allow | Missing Escalation | Missing Evidence | Overblock |
|---|---:|---:|---:|---:|---:|---:|---:|
| admissible_rules_only_v0 | 8 | 0 | 100% | 0% | 0% | 0% | 0% |
| frontier_direct_gemini_v0 | 8 | 0 | 100% | 0% | 0% | 0% | 0% |

## Interpretation

This run validates that Admissible can execute a live external provider path end-to-end:

case envelope → provider decision → schema parsing → scoring → trace JSON → static HTML viewer.

The result should be treated as a live demo smoke pass, not as a stable benchmark claim.

## Limitations

- Only 8 Tier 1 enriched seed cases.
- Cases are hand-authored and already envelope-enriched.
- Gemini is used as a frontier-direct baseline, not as a separate extractor over arbitrary agent outputs.
- No claim is made about general model superiority or benchmark performance.
- Results may vary across provider versions, model settings, and future runs.

## Next Step

The next milestone is to connect a terminal-agent frontier source such as Claude Code, Codex, or Cursor CLI, then have Admissible evaluate proposed side-effecting actions before execution.
