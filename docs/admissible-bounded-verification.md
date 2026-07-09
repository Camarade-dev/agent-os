# Admissible bounded verification (slice ADMISSIBLE_EXECUTION_025)

Bounded verification is **not** shell authority. It is a tiny, explicit,
allowlisted read-only check layer that Admissible can run after bounded local
file execution to attach **verification evidence** to a governed run.

## What this is

After the bounded local executor writes admitted files and records sha256
**write evidence**, an operator (or test) can call
`ControlSurfaceController.verify_bounded_local_workspace()` to run deterministic
checks against the workspace. Results are stored as `verification_records` on
`RunLoopState`, separate from `evidence_records`.

This strengthens the governed multi-turn local build demo: Admissible can now
say not only *these admitted local writes occurred*, but also *these local
checks were run under a bounded verification policy*.

## What this is not

- Not arbitrary shell execution
- Not npm, package install, network, or deploy
- Not auto-run on ingest or model proposals
- Not a broadened executor capability

Verification never executes model-proposed commands. It only runs check ids from
`ALLOWED_VERIFICATION_CHECKS` in `admissible/execution/bounded_local_verification.py`.

## Verification model

| Type | Role |
|------|------|
| `VerificationRequest` | One allowlisted `check_id` plus optional `target_paths` |
| `VerificationResult` | Pass/fail outcome for one check with message and payload |
| `VerificationEvidence` | One explicit verification run: profile, results, overall status |

Verification evidence is persisted in `run_loop.verification_records` (dict
serialization). Write evidence remains in `run_loop.evidence_records` with
`source="bounded_executor"` and types like `bounded_local_write`.

## Allowlisted checks (v0)

| Check id | What it verifies |
|----------|------------------|
| `files_exist` | Expected demo files exist in the workspace |
| `files_non_empty` | Expected demo files have non-zero size |
| `sha256_matches_write_evidence` | Current file digests match the latest bounded write evidence per path |
| `html_local_asset_references` | `index.html` link/script refs are local-only |
| `no_external_references` | No http(s), CDN, or network URLs in HTML/CSS/JS |
| `node_syntax_check` | Optional `node --check game.js` when Node is available |

The default profile `tiny_game_demo` runs the first five checks. Node syntax
check is opt-in via `include_node_syntax_check=True` because it is the only
check that may invoke a tightly bounded subprocess.

## How to trigger verification

Explicit only — same human-triggered invariant as bounded execution:

```python
controller.verify_bounded_local_workspace({
    "workspace_path": str(workspace),
    "profile": "tiny_game_demo",
})
```

HTTP adapter: `POST /api/queue/verify_bounded_local_workspace`

Verification is **not** called automatically after `execute_bounded_local_batch()`.

## Control Surface / state view

`state_view()` exposes a derived `verification_summary`:

- `verification_count`
- `readiness` — `not_run`, `pass`, or `fail`
- `latest` — most recent `VerificationEvidence` dict
- `passed_count` / `failed_count` for the latest run

Write evidence counts in `run_timeline.evidence_count` are unchanged; verification
runs do not inflate write-evidence totals.

## How this strengthens the demos

| Demo | Before | After slice 025 |
|------|--------|-----------------|
| Multi-turn local build (023) | Files written + sha256 write evidence | Optional post-build verification pass |
| Blocker/recovery loop (024) | Four turns, 8 write evidence records | Verification can confirm local-only assets and integrity after recovery |

Recommended demo flow after Turn 4 batch execution:

1. `execute_bounded_local_batch()`
2. `verify_bounded_local_workspace(profile="tiny_game_demo")`
3. Inspect `verification_summary.readiness == "pass"`

## Tests

`tests/test_admissible_bounded_verification.py` covers:

- verification passes after the four-turn recovery demo
- sha256 tampering detection
- external reference and missing-file failures
- rejection of arbitrary command strings
- verification records stored separately from write evidence

## Remaining gaps before ADMISSIBLE_UX_026 and live demo

1. **Product-grade run timeline UX** — surface verification status in the HTML
   harness (counts/readiness only; no product-grade polish yet).
2. **Continuation integration** — optional mention of latest verification status
   in evidence-grounded continuation text.
3. **Benchmark wiring** — record verification pass/fail in demo readiness reports.
4. **Live Cursor demo** — operator step to run verification after final batch
   execution and show pass/fail in Control Surface.
5. **Additional profiles** — only `tiny_game_demo` exists today; other governed
   demos would need their own allowlisted check profiles.

## Related docs

- `docs/admissible-multi-turn-local-build-demo.md`
- `docs/admissible-blocker-recovery-loop-demo.md`
- `docs/admissible-evidence-grounded-continuation.md`
- `docs/admissible-control-surface.md`
