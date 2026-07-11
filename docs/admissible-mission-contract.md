# Admissible mission contract

`MissionContract` is the canonical, versioned, deterministic representation of a submitted goal. The raw goal is retained verbatim with raw and normalized SHA-256 values. Summaries, plans, ledgers, proposals, and progress views are projections; none may narrow or replace it.

The contract keeps explicit user requirements distinct from deterministic inferences, verifier implementations, agent proposals, and execution evidence. Structural parsing runs before lexical classification. It preserves numbered acceptance criteria one-to-one, exact nested paths, architecture and dependency choices, execution boundaries, non-goals, quantities, thresholds, conjunction-bearing source text, ambiguities, and unsupported fragments.

Exact paths are semantic: `game.js` does not satisfy `src/game.js`. Same-basename/different-directory proposals are diagnostics for likely misplaced substitutes, never proof of path satisfaction.

Every mandatory ledger criterion receives a verification disposition. Unsupported runtime verification and required human observation remain visible and open. Passing every currently implemented check is therefore not equivalent to satisfying the mission.

Completion is authorized only by `evaluate_completion_eligibility`. It requires a complete contract, complete contract-to-ledger and verification-plan coverage, terminal satisfaction or recorded waiver for every mandatory criterion, exact path and architecture conformance, no unresolved ambiguity or substitute conflict, no blocker, and no pending useful operation. Imported historical `completed` outcomes remain audit evidence but are re-evaluated canonically.

The isolated agent workspace contains `.admissible/mission-contract.json`. Instructions identify that artifact, its SHA, the raw-goal SHA, open criteria, exact paths, architecture constraints, and verifier capability gaps.

## Runtime observability extraction (Run 043)

`extract_runtime_observability_intent()` deterministically parses typed runtime-observability
intent out of the raw goal and requirement/criterion text — debug interfaces
(`window.__NAME__`), snapshot field lists, `?debug=1`-style query flags, numeric thresholds,
named keyboard controls, temporal/lifecycle requirements, and stability requirements — using
only generic structural phrase patterns, never a hard-coded field or game name. Every
verification disposition now draws from one canonical vocabulary,
`VERIFICATION_DISPOSITIONS` (`deterministic_static`, `deterministic_structural`,
`deterministic_runtime`, `human_observation_required`, `evidence_required`,
`unsupported_verifier`, `ambiguous_requirement`); `deterministic_static` and
`deterministic_runtime` were added in this slice. See
[admissible-bounded-browser-runtime-verification.md](admissible-bounded-browser-runtime-verification.md)
for the full runtime verifier this feeds.

## Runtime evidence still flows through this same authority (Run 044)

RUN_044 wires that runtime verifier into the high-autonomy governed run
(see
[admissible-high-autonomy-governed-loop.md](admissible-high-autonomy-governed-loop.md#run-044-runtime-verification-orchestration)),
but adds no second completion authority. `evaluate_completion_eligibility()`
is still the only function that ever decides `completed`; the runtime
orchestrator only ever writes runtime evidence onto the same acceptance
ledger a static or human-observation path would use
(`apply_runtime_evidence_to_ledger`), so every existing invariant here
(unsupported/gap criteria block completion, a static-disposition criterion
can never be terminally satisfied by a runtime pass alone, a policy
violation withholds an otherwise-passing runtime result) is enforced for
free through this one gate — never re-implemented or weakened by the
orchestrator.
