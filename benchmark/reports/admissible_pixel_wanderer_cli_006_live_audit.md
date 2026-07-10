# Pixel Wanderer `pixel-wanderer-cli-006` live audit

## Exact milestone

`ADMISSIBLE_RUN_038_LIVE_RUN_EFFICIENCY_CLOSURE_AND_GOVERNANCE_HARDENING` uses the first real long-running callable Cursor Agent session, `pixel-wanderer-cli-006`, as the canonical regression case. The source run reached 12/12 model turns and produced `index.html`, `style.css`, `game.js`, and `LOCAL_DEV.md`. It did **not** produce a governed completed/incomplete result: it stopped at the turn ceiling with `verification_readiness=not_run`.

## What worked

- Cursor Agent remained callable across multiple turns in proposal-only plan mode.
- The UTF-8 instruction file, safe file-pointer prompt, and single-line adapter reached the backend.
- Invocation results survived the callable-backend handoff and were ingested durably.
- Only the bounded executor changed target files.
- Eleven bounded execution records covered writes, overwrite states, list/read inspection, and the final verification-oriented reads.
- An explicit operator retry recovered one exit-code-zero, whitespace-only stdout incident.

These facts establish callable transport and bounded execution viability. They do not establish autonomous task completion.

## Defects found

1. Turn 12 ended the run immediately after verification reads, before deterministic verification and closure.
2. The prompt optimized for the smallest individual operation, generating roughly one useful operation per model invocation.
3. Identical `LOCAL_DEV.md` content with the same sha256 was written twice.
4. Model prose saying “Human decision required” created approval gates even when a separately extracted concrete local write evaluated `ALLOW`.
5. Equivalent and already-covered plan gates accumulated and were proposed again.
6. Seven human decisions were recorded for local or stale decision-only gates.
7. Execution totals mixed mutations, reads, lists, duplicates, and verification evidence.
8. Exported `blocked_action_count` did not match the visible active blocker count.
9. No acceptance ledger, structured completion candidate, or verified final outcome existed.
10. Exit code 0 plus whitespace-only stdout was labeled malformed content instead of an empty result.
11. CLI response text could be decoded through a platform default and surface UTF-8 mojibake.
12. Browser Step and auto-run lacked a server-side per-session single-flight guard.

## Cost and turn analysis

The four independent final files fit one bounded proposal batch, yet the run used repeated model turns to surface individual creates, overwrites, inspections, gate restatements, and a duplicate write. The dominant avoidable costs were one-operation continuations, re-proposed completed work, pseudo-gate resolution turns, and closure being attempted only after the work budget was consumed.

Post-038, the default response bound permits eight structured operations and 256 KiB of proposed UTF-8 write content. A four-file Pixel Wanderer batch therefore fits one response while path, content, admission, and executor guards remain unchanged. Two of twelve turns are reserved for completion-first closure; deterministic verification consumes no model turn.

## Human-intervention analysis

The seven recorded decisions were not evidence of seven genuine authority boundaries. Model wording is not policy authority. A gate that merely asks to approve the same concrete `ALLOW` write is suppressed; equivalent gates merge; and an executed newer file state supersedes a stale gate without another approval. Genuine `REFUSE`, `REQUEST_MORE_EVIDENCE`, sensitive overwrite, destructive/irreversible action, external authority, and unresolved user-choice gates remain human-critical.

## Execution and evidence analysis

The original 11 execution records included useful writes, inspection, and one duplicate mutation. That aggregate could not answer how many unique file states were produced or how much work was avoided. Post-038 records use canonical operation fingerprints and one of: `executed_mutation`, `executed_read`, `executed_list`, `duplicate_noop`, `already_satisfied_noop`, `blocked`, or `failed`. The duplicate `LOCAL_DEV.md` proposal links to its original execution and performs no write. A write whose proposed sha256 already matches disk closes as `already_satisfied_noop`.

## Closure failure

The source run had enough local evidence to start verification, but the generic max-turn transition won before a verification result and completion contract could be produced. Therefore the honest original outcome is: **budget ceiling reached; completion unknown; verification not run**. It must not be reported as a completed autonomous task.

## Expected post-038 behavior

- Turn 10 of a 12-turn run enters completion-first mode; optional polish and broad new work stop.
- Any response already received is fully ingested and its admitted operations finish even at the budget boundary.
- Generic local checks verify the eight fixture criteria without shell, browser automation, package manager, or network access.
- Completion is authorized only when every mandatory criterion is `verified_pass` or human-waived, no active human-critical action exists, no useful admitted operation remains, and verification is final.
- Otherwise the run records `incomplete`, `failed`, `stopped_by_budget`, or `stopped_by_operator` with completed criteria, unmet criteria, pending useful operations, and an exact reason.
- Backend metrics separate invocations, retries, and `empty_success`; execution metrics separate useful writes, unique file states, duplicates, overwrites, reads, lists, and verification checks.
- The session export, high-autonomy summary, governed overview, and UI all use `active_blocked_count`: currently active, non-completed, genuinely blocking actions only.
