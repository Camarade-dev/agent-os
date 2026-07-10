# Admissible mission contract

`MissionContract` is the canonical, versioned, deterministic representation of a submitted goal. The raw goal is retained verbatim with raw and normalized SHA-256 values. Summaries, plans, ledgers, proposals, and progress views are projections; none may narrow or replace it.

The contract keeps explicit user requirements distinct from deterministic inferences, verifier implementations, agent proposals, and execution evidence. Structural parsing runs before lexical classification. It preserves numbered acceptance criteria one-to-one, exact nested paths, architecture and dependency choices, execution boundaries, non-goals, quantities, thresholds, conjunction-bearing source text, ambiguities, and unsupported fragments.

Exact paths are semantic: `game.js` does not satisfy `src/game.js`. Same-basename/different-directory proposals are diagnostics for likely misplaced substitutes, never proof of path satisfaction.

Every mandatory ledger criterion receives a verification disposition. Unsupported runtime verification and required human observation remain visible and open. Passing every currently implemented check is therefore not equivalent to satisfying the mission.

Completion is authorized only by `evaluate_completion_eligibility`. It requires a complete contract, complete contract-to-ledger and verification-plan coverage, terminal satisfaction or recorded waiver for every mandatory criterion, exact path and architecture conformance, no unresolved ambiguity or substitute conflict, no blocker, and no pending useful operation. Imported historical `completed` outcomes remain audit evidence but are re-evaluated canonically.

The isolated agent workspace contains `.admissible/mission-contract.json`. Instructions identify that artifact, its SHA, the raw-goal SHA, open criteria, exact paths, architecture constraints, and verifier capability gaps.
