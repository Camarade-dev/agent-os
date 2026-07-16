# Admissible native delegated-executor canary

## Status and boundary

Act 2A is an unrun, one-shot canary harness. No live Cursor, Codex, Claude, or
other provider invocation has occurred. It is not an OS sandbox, credential
isolation system, global filesystem monitor, command-level monitor, push
broker, or production containment boundary.

A native agent remains a black box for inspection, edits, shell use, npm, and
local Git inside its assigned disposable repository. Admissible governs the
single launch, evidence, independent verification, checkpoint capture, and
state transition only. Provider prose is bounded transcript evidence, never
proof of a commit, test, or feature.

## Locally attested Cursor backend

`PREFLIGHT_READY` is emitted only after canonical local `cursor-agent`
discovery identifies an installed command and the selected local Node package
supplies a strict, locally inspected installation chain: canonical shim,
package root, `package.json`, expected package identity, declared
`bin.cursor-agent` mapping, and the exact mapped launcher inside that package
root. The executable, shim, manifest, launcher, and every authoritative
launcher-prefix file must be canonical, non-redirecting regular files with
recorded hashes, byte counts, and filesystem identities. The manifest/bin chain
must resolve exactly to the launcher used by the native argv.

The attestation also records non-provider `--version` and `--help` probe argv,
exit codes, bounded stdout/stderr hashes, locally advertised arguments, native
argv template, selected model, and one fingerprint. This is a local
installation-chain attestation, not cryptographic publisher verification. If a
local distribution lacks a stable verifiable manifest/bin chain, preflight is
`PREFLIGHT_BLOCKED`; arbitrary renamed executables and JavaScript launchers
cannot become ready by printing Cursor-looking text.

The required local advertisement covers `--print`, `--force`,
`--output-format stream-json`, `--trust`, and `--model`. This establishes local
capability advertisement only. It does not establish that a native write will
succeed; that remains the separately authorized live-canary experiment.

Before spawn the executor repeats discovery, manifest/package/bin validation,
lstat/hash/identity checks, and local probes. A changed shim, manifest,
executable, launcher, help/version output, advertised argument, or
contradictory attestation blocks without spawning. Web documentation is not
runtime authority.

The prompt is one final argv item and begins with a fixed harness-controlled
header. Mission text is embedded in that item and cannot become an option-like
first argument.

## Attestation classes

Two explicit attestation classes exist and are bound into the attestation,
request, and owner authorization payload:

- `PACKAGE_BIN_PROVENANCE` — the mode described above; preferred whenever its
  manifest/bin requirements are satisfied.
- `LOCAL_WRAPPER_CHAIN` — a weaker, explicitly owner-accepted class for the
  locally observed `cursor-agent.cmd → cursor-agent.ps1 → versions/<latest>
  node.exe index.js` chain, whose runtime package intentionally declares no
  `bin.cursor-agent`. It attests the winning OS command resolution
  (which/where/Get-Command/PATH/PATHEXT agreement), strict-parsed wrapper
  bytes and semantics, deterministic version selection, and exact
  runtime/entry/manifest identity — and explicitly does **not** attest
  Anysphere publisher identity, Cursor desktop ownership, package-manager
  ownership, payload signatures, CLI capability behavior (no version/help
  probe runs in this mode), or production trustworthiness. Its readiness
  reason is `LOCAL_CURSOR_WRAPPER_CHAIN_ATTESTED_FOR_EXPERIMENT`. A failed
  package-bin attestation never downgrades to this class; it requires
  `--attestation-class wrapper-chain` plus an owner digest over a payload
  naming the class and every non-claim. See
  `admissible-cursor-wrapper-chain-attestation.md` for the forensic decision.

In wrapper-chain mode the configuration accepts only the bare canonical
`cursor-agent` command; every launcher file is derived from host discovery,
so caller-supplied wrapper roots, fake manifests, or injected attestations
cannot become production-ready. Immediately before spawn the full discovery,
wrapper parsing, version inventory/selection, and every file identity are
recomputed and must match the authorized attestation exactly; a newly added
later version invalidates the authorization.

## Request, result, and durable sidecars

The immutable request is restricted to execution attempt `0`. It binds the
session, gate, mission and contract fingerprints, canonical workspace and
identity, canonical evidence and bounded artifact roots with identities,
complete backend attestation, timeout/output limits, cleanup policy, prompt
hash, and request fingerprint. No PATH-dependent executable or shell fragment
is authoritative. Parsing a persisted request is inert: execution and final
reconstruction require a fresh local re-attestation that exactly matches the
persisted backend record.

`NativeDelegatedExecutor.execute()` returns a private, transient,
exact-object-issued result handle. The write-once sidecar accepts only that
handle, consumes it after durable validation, and rejects plain, deserialized,
or lookalike results. Result booleans are checked against raw observations:
source mutation, sibling mutation, workspace material change, cleanup, and
orphan status cannot contradict their recorded inputs. Final HEAD, ancestry,
commit count, complete message, changed paths, remotes, status, and material
tree are independently recomputed from the assigned workspace rather than
accepted as self-fingerprinted success claims.

Request, result, behavioral-verifier, capture-attempt, and terminal records use lock-protected
write-once publication, file fsync, directory durability attempt, and reload
validation. A committed-but-directory-durability-uncertain write is a blocking
boundary, never full durability. Results verify stdout/stderr artifacts before
and after publication. Behavioral script/stdout/stderr artifacts and their
strict evidence record use this same durable write-once boundary; no checkpoint
may follow behavioral durability uncertainty.

## Measured path boundary

Source repository, workspace, canary parent, evidence/store roots, executable,
launcher files, and material snapshots are checked with lstat-style,
reparse-aware validation. Symlinks, Windows junctions, redirecting reparse
points, malformed roots, and overlapping source/work/evidence locations are
refused. Sibling inventories recursively hash contents and include filesystem
identity, so same-name replacement changes are visible.

The invocation-artifact directory is a pre-created bounded child of the exact
evidence store. Its containment, existing components, reparse status, and
identity are validated before request publication, before process invocation,
and before each artifact creation; an escaped artifact root cannot cause a
native process to start.

This remains before/after measured observation, not continuous containment. A
mutation perfectly restored between observations is not detected. The harness
does not claim detection outside its measured source repository and canary
parent.

## Fixture and immutable behavioral proof

The fixture is a clean, deterministic one-commit Git repository with no remote,
no dependencies or lifecycle hooks, and a Node-built-in `npm test` script. The
mission requires source, test, and README changes.

The repository's own `npm test` remains a fixed checkpoint command, but it is
not sufficient success authority. The harness writes an immutable Node-built-in
behavioral verifier outside the mutable repository tests. It imports the public
implementation with isolated in-memory storage and verifies fresh state,
reload, lower-score preservation, higher-score replacement, malformed state,
and deterministic repeated observation. Script/stdout/stderr hashes are durable
evidence.

## Pre-capture and capture contract

Before `capture_checkpoint`, the harness requires: one successful process; no
timeout, cleanup uncertainty, source mutation, sibling mutation, or remote;
changed HEAD; exactly one new commit; exact complete commit message
`feat: add deterministic high-score persistence`; clean worktree; every
required source/test/README path changed; and a passing immutable behavioral
verifier. A zero exit, mutable test pass, or provider claim alone cannot reach
a checkpoint.

Each pre-capture failure creates a write-once terminal record and leaves the
delegated state at `GATE_EXECUTING`. Before actual capture, a durable
capture-attempt record is published. Capture failure receives a terminal
record; a persisted attempt without a completed checkpoint is ambiguous and is
never replayed. There is no repair, retry, audit, gate pass, advancement, push,
or second provider invocation.

Act 1 may legitimately capture failed command evidence as an observation. Act
2A constructs that successor transiently, but persists `CHECKPOINT_CAPTURED`
only when every exact active-contract verification command is present and
`PASSED` with exit code zero, no timeout, truncation, or cleanup uncertainty.
A failed verification checkpoint leaves durable state at `GATE_EXECUTING`,
writes one terminal record, and consumes the one capture attempt.

Success is emitted only after reloading request, freshly matching backend
attestation, result, native artifacts, behavioral evidence, capture-attempt
record, delegated state, checkpoint, and every checkpoint artifact hash/size
from disk. Reconstruction binds the unique capture attempt to the exact run,
request/result/behavioral fingerprints, plan, active gate contract, required
command identities, expected `CHECKPOINT_CAPTURED` outcome, state revision,
and persisted checkpoint. The reconstructed
state must be exactly `CHECKPOINT_CAPTURED` with no audit or repair history.

## Future live authorization

The future-only entry point is `python -m admissible.delegated_gate.native_canary`.
Its order is source clean/HEAD validation, local backend attestation,
authorization-payload construction, phrase validation, fresh-run validation,
then—and only then—run-root/fixture creation and the single native launch. The
fresh run root is named exactly for the run ID, so an authorization payload
cannot be silently reused for another root.

`--preflight-only` prints the canonical non-secret authorization payload and
attestation without creating a workspace or invoking a provider. The owner
digest is SHA-256 over `owner_phrase_utf8 + NUL + canonical_payload_bytes` and
is never persisted or printed. The payload binds exact source HEAD, clean-state
requirement, fresh run ID/session, mission/gate fingerprints, backend/executable
identity, model, budgets, fixture version, commit message, and canonical
run/evidence paths. A different HEAD, backend, model, timeout, mission, root,
or run ID requires a new authorization digest; a partial or completed run ID is
not fresh.

Hard budgets remain provider/native attempts `1/1`, repair/auditor/retry
`0/0/0`. No independent model auditor exists, and no live canary has run.
