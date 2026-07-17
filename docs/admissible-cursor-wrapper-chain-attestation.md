# Cursor wrapper-chain attestation (Act 2A.2 forensic decision)

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

- the exact winning OS command resolution for `cursor-agent`
  (`shutil.which`, `where.exe`, PowerShell `Get-Command` when available,
  PATH/PATHEXT semantics), blocking on contradictory or ambiguous resolution;
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
- production trustworthiness.

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
invocation. Production wrapper-chain discovery is host-anchored: arbitrary
caller-supplied wrapper roots, fake manifests, injected attestations, or
environment bypasses cannot reach production readiness; the test discovery
seam is explicit constructor injection unreachable from the production CLI.

Act 2A.3C retains
`admissible_cursor_wrapper_chain_attestation_v1` because the serialized shape
did not change and no live canary was authorized or run. Loading now rejects
every nonzero authoritative directory size instead of repairing it. Every
wrapper-chain preview, fingerprint, and canonical-byte hash created before the
normalization repair is invalid, including a preview whose raw directory size
happened to be zero. A fresh post-repair, post-commit static attestation and
clean-HEAD real-CLI payload preview are mandatory before any owner decision.

## Status

No live Cursor invocation has occurred under this class. The current work does
not demonstrate native write behavior. This adapter is not verified official
Cursor provenance and is weaker than package-bin or publisher provenance;
production use would require a stronger trust and isolation posture.
