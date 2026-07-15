# neon-serpents-live-002 — archived real live-run evidence

**Classification: real live-run evidence. This is NOT a test fixture.**

These artifacts are the byte-for-byte recovery of the successful Admissible V0
Slice-4 two-turn governed Cursor run `neon-serpents-live-002`. They were
recovered from the Windows temporary run directory
`C:\Users\stris\AppData\Local\Temp\admissible-v0-neon-live-002-20260715-180833`
and copied without modification. The generated target files were **not**
reconstructed, reformatted, or regenerated.

The canonical facts recorded for this run were independently re-verified against
the persisted session before archiving:

| fact | value |
| --- | --- |
| Cursor invocations | 2 |
| consumed results | 2 |
| admitted operations | 8 |
| physical writes | 8 |
| durable receipts | 8 |
| FileEvidence records | 8 |
| remaining mandatory paths | 0 |
| structural verification | passed (8 file checks) |
| final phase | `awaiting_human` |
| revision | 16 |

Every one of the 8 generated target files under `target/` was verified to hash
(SHA-256) exactly to its persisted `FileEvidence` entry in `session.v0.json`.

## Contents

- `session.v0.json` — the durable, immutable V0 session state (phase `awaiting_human`).
- `target/` — the 8-file generated Neon Serpents application. Entry point: `target/index.html`.
- `neon_serpents_mission.txt` — the operator mission text.
- `agent/` — the isolated agent-workspace proposal artifacts from the run.
- `manifest.json` — SHA-256 + byte counts for the **recovered Slice-4 source
  evidence** (the recovered agent/session/target artifacts), plus the canonical
  facts and the persisted target evidence hashes. It intentionally does not
  cover artifacts produced after the recovered run.
- `runtime-store/` — the **Slice-5A runtime evidence**. This was produced later
  by the bounded browser verifier (one PASS attempt); it was **not** part of the
  recovered Slice-4 run. It contains the immutable runtime result sidecar
  (`*.runtime.json`) plus its screenshot and serialized DOM document.
- `MANIFEST.sha256` — the **umbrella archive-integrity manifest**. It covers
  **every committed file** under this archive (this README, `manifest.json`, the
  recovered agent/session/target artifacts, and the Slice-5A runtime sidecar,
  screenshot, and document) as deterministic, sorted, repository-relative
  `<sha256>  <path>` lines over exact bytes. `MANIFEST.sha256` excludes only
  itself (self-exclusion is intentional and standard) and transient lock/temp
  files (which must never be present in the archive; runtime advisory locks are
  machine-local and live outside this tree). Regenerate/verify with
  `admissible.browser_runtime.archive_integrity`.

## Use in Slice 5

This archived `target/` tree is the **live target** for the Slice 5A bounded
browser verification run. The verifier must not modify any file here; the
`session.v0.json` is the persisted run to which exactly one runtime verification
result and (Slice 5B) one human disposition are attached.

Deterministic test fixtures for the verifier live separately under
`tests/fixtures/` and are clearly classified as fixtures — they do not replace
this real evidence.
