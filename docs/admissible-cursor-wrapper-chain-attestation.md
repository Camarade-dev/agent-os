# Cursor wrapper-chain attestation (Act 2A.3E deterministic authority)

## Forensic result

Act 2A.1 ended in `ACT_2A_1_CURSOR_PROVENANCE_NOT_ESTABLISHED`. Read-only
forensics established the mechanical local launch chain:

`cursor-agent` → `cursor-agent.cmd` → adjacent `cursor-agent.ps1` →
deterministic latest-version selection under the adjacent `versions/`
directory → the selected version's bundled `node.exe index.js`.

The selected package is `@anysphere/agent-cli-runtime`. Its manifest
intentionally declares **no** `bin.cursor-agent` mapping, and no npm, pnpm,
Yarn, Corepack, registry, App Path, or installer metadata supplies the missing
command mapping. The command-to-launcher mapping authority therefore comes
from the exact audited wrapper bytes, not from any package manifest. The local
bundle has no verified ownership link to the separately installed
Anysphere-signed Cursor desktop application, and the launcher JavaScript and
auxiliary payloads are unsigned.

## Owner decision

The missing publisher/installer provenance remains explicit. For one local
experimental canary only, a second, weaker, clearly named attestation class is
accepted:

- `PACKAGE_BIN_PROVENANCE` — the existing stricter package/manifest/bin mode.
  It remains available and preferred whenever its requirements are satisfied.
- `LOCAL_WRAPPER_CHAIN` — the weaker class defined here. A failed package-bin
  attestation is never silently reinterpreted as a wrapper-chain attestation;
  the class must be explicitly configured and explicitly owner-authorized.

## What LOCAL_WRAPPER_CHAIN attests

- deterministic cmd-compatible resolution of the fixed bare command
  `cursor-agent` under the exact ordered Windows `PATH` and `PATHEXT` strings.
  The v2 record binds both complete ordered strings and their SHA-256 values,
  the winning PATH/PATHEXT indices, the authoritative PATH entry, and every
  material candidate at the winning precedence position. Resolution is
  case-insensitive, rejects caller-supplied command paths, and accepts only a
  canonical non-redirecting regular-file winner with exact identity and hash;
- exact canonical and physical-identity agreement between that deterministic
  winner and `shutil.which("cursor-agent")` observed against the same captured
  environment. One missing result, differing paths or identities, or any
  PATH/PATHEXT change at pre-spawn re-attestation blocks;
- the complete PowerShell `Get-Command cursor-agent -All` inventory, normalized
  independently of inventory enumeration order. It must contain the same
  physical `.cmd` winner and the adjacent `.ps1`, must record `.ps1` as the
  PowerShell-preferred command, and rejects aliases, functions, application
  aliases, pathless commands, redirecting entries, contradictory cmd winners,
  and every out-of-root candidate;
- the exact winning `cursor-agent.cmd` bytes, accepted only by a strict
  non-general parser: `powershell.exe -NoProfile -ExecutionPolicy Bypass`
  invoking the adjacent same-name `.ps1` with unmodified `%*` forwarding, no
  other command, no cwd change, no shell operators or redirection;
- the exact `cursor-agent.ps1` bytes, accepted only by a bounded recognizer of
  the observed launcher grammar: derive own directory, optional adjacent
  `node.exe index.js` shortcut (which must be inactive), enumerate only the
  adjacent `versions` directory, filter by the observed version grammar
  `^\d{4}\.\d{1,2}\.\d{1,2}(-\d{2}-\d{2}-\d{2})?-[a-f0-9]+$`, sort
  deterministically, select the latest single version, execute exactly that
  version's `node.exe index.js` with `$args` forwarded unchanged. Any
  unrecognized executable behavior fails closed;
- the recomputed version inventory and deterministic selection (a date-key tie
  is ambiguous and blocks);
- SHA-256, byte count, filesystem identity, and reparse/redirect absence for
  every authoritative file: wrappers, `node.exe`, `index.js`, `package.json`,
  and any selected-version wrapper copies (which must be byte-identical to the
  top-level wrappers);
- normalized local directory identity for the wrapper root and selected
  version root. Windows directory `st_size` is unstable and is never copied
  into signed authority: directory `size` is canonical `0`, while
  device/inode or Windows file identity, mode/type, file attributes, mtime, and
  non-reparse status remain bound. Regular-file size remains exact and
  authoritative;
- containment of every launcher file inside the canonical wrapper/version
  roots;
- stability between attestation/authorization and spawn: immediately before
  spawn, discovery, both wrapper parses, the version inventory and selection,
  and every file identity are recomputed and must match exactly. A newly
  added later version — or any other change — invalidates the run and its
  authorization payload.

Windows Authenticode evidence for the bundled `node.exe` is recorded as
context only (the OpenJS signature is not authority for `index.js`).

## Non-authoritative where.exe diagnostic

`where.exe` is retained only as review context because its availability and
empty-result behavior are not reliable in this execution environment. The
separate diagnostic records its exact executable path/identity when available,
argv, exit code, stdout/stderr byte lengths and SHA-256 values, and parsed
candidates. Its explicit statuses are `MATCHING_RESULT`,
`CONTRADICTORY_RESULT`, `EMPTY_RESULT`, `EXECUTION_ERROR`, and `UNAVAILABLE`.

A successful matching result permits readiness. A successful contradictory
result blocks. Empty output (including exit 1), nonzero/error observations, or
an unavailable executable do not participate in authority and do not prevent
the deterministic resolver, `shutil.which`, PowerShell inventory, and wrapper
identities from deciding readiness.

The diagnostic is emitted separately by `--preflight-only`. It is excluded
from command-resolution authority, the backend-attestation fingerprint, the
authorization-payload fingerprint, canonical owner-digest bytes, persisted
requests, and pre-spawn equality. Variation in diagnostic bytes alone therefore
cannot change any signed authority.

Directory identity remains a local, non-cryptographic observation. It is not
complete filesystem containment or publisher provenance. The complete
matching version inventory, deterministic selected version, exact child-root
relationships, and every authoritative launcher file's byte count, identity,
and SHA-256 provide the separate material evidence.

## Explicit non-claims

The attestation carries a fixed claim set and non-claim list, and validation
rejects any record that overclaims. It does **not** attest:

- Anysphere publisher identity;
- ownership by the signed Cursor desktop installation;
- package-manager or installer ownership;
- cryptographic integrity or signature of the JavaScript payload;
- native CLI argument/capability behavior (no `--version`/`--help` probe is
  run in this mode; behavior stays experimentally unproven);
- production trustworthiness;
- Windows-wide command behavior under a different PATH/PATHEXT environment;
- protection against a hostile local process changing the environment.

The readiness reason is `LOCAL_CURSOR_WRAPPER_CHAIN_ATTESTED_FOR_EXPERIMENT`,
never `CURSOR_INSTALLATION_PROVEN`. The truthful record that the manifest
declares no `bin.cursor-agent` is stored as an observation, not treated as
proof of anything.

## Authorization and boundary

The complete wrapper-chain attestation fingerprint is bound into the native
execution request, the persisted sidecar, final reconstruction, and the
run-bound owner authorization payload. The payload names the attestation
class and the full non-claim list; the owner digest therefore authorizes that
exact weaker mode, its unproven CLI behavior, and exactly one bounded provider
invocation. Production wrapper-chain discovery is host-anchored. The private
deterministic test discovery fixture is unreachable from production `main()`.
Production accepts no caller PATH/PATHEXT, wrapper root, command candidate,
resolver JSON, fake attestation, test-mode environment variable, or
deserialization bypass. Parsed requests remain inert until fresh host
re-attestation matches them exactly.

Act 2A.3E introduces
`admissible_cursor_wrapper_chain_attestation_v2` because command-resolution
authority changed materially. The former
`admissible_cursor_wrapper_chain_attestation_v1` is inert historical data:
loading rejects it before it can authorize a new request, restart, owner
payload, or live canary, even if it is refingerprinted.

The outer authorization schema remains
`admissible_native_canary_authorization_v3`: its field shape did not change,
production constructs it only from a freshly validated v2 attestation, and it
binds the new backend fingerprint and expanded exact non-claim list. The live
CLI does not ingest a caller-provided payload. No v1 owner digest or live run
exists. Every earlier wrapper-v1 attestation, v3 preview, payload fingerprint,
canonical-byte hash, and digest input is invalid. Implementation-time vectors
are `PRE_COMMIT_PROVISIONAL_NOT_AUTHORIZABLE`; a fresh post-commit clean-HEAD
real-CLI preview is mandatory before any owner decision.

## Status

No live Cursor invocation has occurred under this class. The current work does
not demonstrate native write behavior. This adapter is not verified official
Cursor provenance and is weaker than package-bin or publisher provenance;
production use would require a stronger trust and isolation posture.
