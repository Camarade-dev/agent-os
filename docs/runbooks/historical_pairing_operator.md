# Historical evaluation pairing — operator runbook

This runbook takes a Windows operator from an installed Admissible distribution
to exactly three published canonical archive documents, using only installed
product and operator entrypoints.

Every value written as `<LIKE-THIS>` is a placeholder. Replace it with your own
value. No placeholder is ever a literal value, and this document deliberately
contains no real secret, no real tag, and no real fingerprint.

---

## 1. Prerequisites and trust model

You need:

* an installed distribution exposing the console scripts `admissible`,
  `admissible-historical-pairing-tag` and
  `admissible-historical-pairing-v4-extract`;
* one real historical wrapper document that carries a top-level
  `authorization_payload` member;
* one local Git repository to use as the launcher's source repository, with a
  clean worktree and a known HEAD;
* a working directory outside both the product repository and the source
  repository, for the files you create below.

Every path you type must be an **absolute**, already-canonical Windows path.
No relative path, `~`, environment-variable reference, or working-directory
guess is ever accepted or repaired for you.

What this workflow establishes, and nothing more:

* an owner asserted one exact post-run evaluation contract (a non-launchable V5
  profile) for one exact historical authorization payload;
* a valid deterministic confirmation tag for that exact pairing authority was
  presented once through the dedicated confirmation channel;
* the three canonical documents are now loadable from the archive.

`actor_id` is **asserted**. It is not authenticated by anything here. The tag is
a symmetric shared-secret message authentication code; it is **not a signature**
and it identifies no person. Publishing the archive is **not an execution**,
result, evidence, eligibility, or verdict claim, and it is **not a confirmation
receipt**.

---

## 2. Locate one real wrapper

Use a wrapper your product already produced. Both accepted wrapper families
carry the payload under one top-level `authorization_payload` member:

* the preflight-only envelope printed by the product's own preflight child;
* the run preflight metadata file `canary-preflight.json` written under a run's
  evidence directory.

Copy exactly one such file to your working directory, for example
`<WORK-DIR>\wrapper.json`.

Only the top-level `authorization_payload` member is ever read. Sibling members
such as `status`, `attestation`, `classification`, `where_diagnostic`,
`local_capability_status` and `durability_capability` are ignored completely.
A wrapper whose `status` says the preflight was blocked or failed still yields
exactly the same payload: the extractor infers nothing from a sibling.

The extractor never looks at neighbouring files. It never lists, globs, or scans
the wrapper's directory, and it never reads an evidence sibling.

---

## 3. Extract the standalone V4 document

```powershell
admissible-historical-pairing-v4-extract --wrapper-file '<WORK-DIR>\wrapper.json' --output-file '<WORK-DIR>\standalone-v4.json'
```

On success the command exits `0`, writes nothing to standard error, and prints
exactly one line:

```text
status=STANDALONE_V4_WRITTEN
```

That line names the file-writing operation and nothing else. It does not mean
the document was verified, admitted, accepted, or that any run succeeded.

Warnings for this step:

* Both paths must be **absolute** and already canonical.
* **No parent directory is created** for you. Create `<WORK-DIR>` yourself
  first; a missing parent is a refusal, not an automatic `mkdir`.
* Publication is **create-only**. An existing output path — file, directory,
  or link — is refused with `error=HISTORICAL_PAIRING_V4_OUTPUT_EXISTS` and is
  never overwritten.
* Publication is not crash-atomic. If the command is killed abruptly it can
  leave a **partial output** behind. Such a file is never silently replaced:
  delete it explicitly before retrying.

Any refusal prints exactly one `error=<CODE>` line to standard error and exits
`3`.

---

## 4. Create the exact-byte secret file

The configured secret is **exactly the bytes of the file**, between 16 and 4096
bytes inclusive. Use a binary-safe writer only.

```powershell
$secret = New-Object byte[] 32; $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($secret); $rng.Dispose(); [System.IO.File]::WriteAllBytes('<SECRET-FILE>', $secret); Remove-Variable secret
```

Warnings for this step:

* Every byte counts: a trailing **newline and NUL** byte, a space, or a tab is
  part of the secret. `Set-Content`, `Out-File`, `>` and `>>` may add a trailing
  newline or a **byte order mark**; never use them for the secret file.
* **Never place the secret in a command line argument**, an environment
  variable, a shell history entry, or a printed value. The product accepts only
  a filesystem locator.
* Do not Base64- or hex-encode the secret and then configure the encoded text:
  the configured secret is the raw file bytes.
* If you need to record the file's identity, record a SHA-256 digest of it in
  your own notes only. Never place that digest in the product configuration.

---

## 5. Create the enablement document

The enablement document is non-secret. It must be strict UTF-8 with no byte
order mark, and it must carry exactly five fields.

```powershell
$enablement = [ordered]@{ schema_version = 'admissible_historical_pairing_enablement_v1'; archive_root = '<ARCHIVE-ROOT>'; payloads = @(@{ payload_id = '<PAYLOAD-ID>'; document_path = '<STANDALONE-V4-FILE>' }); preparation_ttl_seconds = 900; max_preparations = 16 } | ConvertTo-Json -Depth 5; [System.IO.File]::WriteAllBytes('<ENABLEMENT-FILE>', ([System.Text.UTF8Encoding]::new($false)).GetBytes($enablement))
```

`ConvertTo-Json` escapes Windows path separators for you. If you write the JSON
by hand instead, remember that every backslash inside a JSON string must be
doubled.

Warnings for this step:

* `archive_root` and every `document_path` must be **absolute** canonical paths.
* The document must never contain the secret, a tag, or an owner phrase.
* `payload_id` must be 3 to 64 characters of lowercase ASCII letters, digits and
  hyphen, beginning with a letter or digit. Declaration order is the order the
  browser shows.

---

## 6. Launch Admissible

```powershell
admissible `
  --source-repository '<SOURCE-REPOSITORY>' `
  --required-source-head '<REQUIRED-SOURCE-HEAD>' `
  --run-parent '<RUNTIME-ROOT>\runs' `
  --contract-documents-directory '<RUNTIME-ROOT>\contracts' `
  --executable '<BACKEND-EXECUTABLE>' `
  --attestation-class '<ATTESTATION-CLASS>' `
  --ui-port 0 `
  --g2-port 0 `
  --no-browser `
  --historical-pairing-config '<ENABLEMENT-FILE>' `
  --historical-pairing-secret-file '<SECRET-FILE>'
```

The launcher prints exactly one readiness line and then serves:

```text
ui=http://127.0.0.1:<UI-PORT>/ g2_port=<G2-PORT>
```

Open that URL yourself. Drop `--no-browser` if you want the launcher to open it.

Warnings for this step:

* Both historical options are required together. Supplying only one exits `3`
  with `error=HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE` and creates no
  runtime directory, socket, or worker.
* `<RUNTIME-ROOT>` and `<ARCHIVE-ROOT>` must be outside both the source
  repository and the product repository.
* If the feature is off, every historical route answers with exactly the same
  `404 NOT_FOUND` an unknown route receives. There is no "disabled" answer.

---

## 7. Review the configured payload

In the browser, the historical pairing panel lists the configured payloads in
declaration order. The same list is served by:

```text
GET /ui/api/v1/historical-pairings/payloads
```

Each record shows the payload identifier, the payload fingerprint, the document
SHA-256, and the document byte length. No configured document path and no
archive root is ever exposed.

Confirm that the payload fingerprint is the one you expect before continuing.

---

## 8. Author claims, plans and bindings

Fill the three JSON array fields in the browser form:

* **Result Claims** — an ordered array of claim objects.
* **Claim Verification Plan** — an ordered array of verification obligations.
* **Verification Evidence Bindings** — an ordered array of bindings.

Nothing is defaulted, sorted, trimmed, deduplicated, or completed for you. The
page sends exactly what you wrote, in the order you wrote it.

Rules the product enforces:

* every binding must name an obligation that exists in your plan;
* a `CHECKPOINT_COMMAND` obligation may only be bound with
  `CHECKPOINT_COMMAND_AUTHORITY`, and its reference must be a checkpoint command
  the historical profile already declares;
* a `FROZEN_BEHAVIORAL_VERIFIER` obligation may only be bound with
  `FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY`, referencing the profile's own verifier
  digest;
* a `HUMAN_RUBRIC_OBSERVATION` obligation cannot be evidence-bound at all;
* every obligation must declare its negative controls and all six independence
  requirements.

Your asserted actor identifier goes in the actor field. It is recorded as an
assertion and is never authenticated.

---

## 9. Prepare and review the pairing authority

Submit the form. The product answers with the complete owner review:

```text
POST /ui/api/v1/historical-pairings/preparations
GET  /ui/api/v1/historical-pairings/preparations/<PREPARATION-ID>/<PAIRING-AUTHORITY-FINGERPRINT>
```

Read the whole review before continuing. It shows your own claims, plan and
bindings exactly as written, the historical mission context, the historical
authority facts, and the compatibility revalidation. It also shows that the
derived evaluation profile is a V5 profile and is not launchable, that claim
coverage remains `NOT_ASSESSED`, and the complete ordered list of notices.

The review contains no secret and no confirmation tag, and it never states that
an execution happened, that a claim is supported, or that a result was admitted.

---

## 10. Export the public confirmation message

In the browser, use **Download confirmation-message bytes**. The page decodes
the launcher-supplied Base64 and checks the decoded length against the declared
length before offering the file.

If you prefer the command line, copy the Base64 value shown in the review and
decode it with a binary-safe writer:

```powershell
[System.IO.File]::WriteAllBytes('<CONFIRMATION-MESSAGE-FILE>', [System.Convert]::FromBase64String('<CONFIRMATION-MESSAGE-BASE64>'))
```

The exported file is the **complete** message. It **already includes the domain**
constant and the single NUL separator byte, followed by the canonical JSON bytes
of the whole pairing authority document. **Do not prepend**, append, re-frame,
re-encode, trim, or normalize anything before computing the tag.

---

## 11. Verify the message length and SHA-256

```powershell
$expectedLength = <CONFIRMATION-MESSAGE-BYTE-LENGTH>; $expectedHash = '<CONFIRMATION-MESSAGE-SHA256>'; $actual = [System.IO.File]::ReadAllBytes('<CONFIRMATION-MESSAGE-FILE>'); if ($actual.Length -ne $expectedLength) { throw 'declared length mismatch' }; $hash = (Get-FileHash -Algorithm SHA256 -Path '<CONFIRMATION-MESSAGE-FILE>').Hash.ToLower(); if ($hash -ne $expectedHash.ToLower()) { throw 'declared sha256 mismatch' }; 'confirmation message integrity verified'
```

Take `<CONFIRMATION-MESSAGE-BYTE-LENGTH>` and `<CONFIRMATION-MESSAGE-SHA256>`
from the review's own `confirmation_message_byte_length` and
`confirmation_message_sha256` fields. If either check fails, stop: do not
compute a tag over bytes you could not verify.

---

## 12. Compute the tag

```powershell
admissible-historical-pairing-tag --message-file '<CONFIRMATION-MESSAGE-FILE>' --secret-file '<SECRET-FILE>'
```

The helper prints exactly one lowercase 64-character hexadecimal tag and nothing
else. It exits `0`, writes nothing to standard error, and prints no prose.

The helper is independent: it never contacts the product, opens no socket, reads
no archive, and persists nothing.

Warnings for this step:

* **Do not redirect the tag** into a file, a transcript, a clipboard manager, or
  any durable store. Copy the single printed line and paste it once.
* The tag is **deterministic and replayable**: the same secret and the same
  authority always produce the same tag, so an earlier tag can be presented
  again. Acceptance therefore never proves fresh secret possession.
* The tag is **not a signature**, and it is not actor authentication.

---

## 13. Paste the tag

Paste the tag into the browser's dedicated **Confirmation tag** field only.

The page sends it once, in exactly one request header:

```text
X-Admissible-Historical-Pairing-Confirmation
```

Never place the tag in the URL, in a query parameter, in the request body, in an
`Authorization` header, in a cookie, in browser storage, or in an environment
variable. Every one of those is refused and archives nothing.

---

## 14. Confirm

Submit the confirmation. On success the product answers `200` with the outcome
`CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE`, the preparation identifier, the
asserted actor identifier, the three fingerprints, the archived document count,
and the complete ordered limitations list.

The product never returns the tag and never persists it. The preparation becomes
consumed; a second confirmation against the same preparation is refused with
`409 PREPARATION_CONSUMED`.

---

## 15. Verify the three archive documents

```powershell
Get-ChildItem -Recurse -File '<ARCHIVE-ROOT>' | Select-Object FullName, Length
```

Exactly three files must exist:

```text
profiles\<EVALUATION-PROFILE-FINGERPRINT>.native-mission-profile-v5.json
payloads\<TARGET-PAYLOAD-FINGERPRINT>.native-canary-authorization-v4.json
authorities\<PAIRING-AUTHORITY-FINGERPRINT>.historical-evaluation-pairing-v1.json
```

Each filename is its document's own fingerprint. The archived payload bytes are
byte-identical to the standalone V4 document you extracted in step 3.

There is no fourth document. No receipt, status file, manifest, index, actor
record, timestamped possession proof, tag, tag hash, or secret-derived file is
ever written. The archive is **not a confirmation receipt**: its existence alone
never proves that any tag was ever presented.

---

## 16. Restart and ephemeral preparation state

Preparation, review, and consumed status are in-memory process state.
**Restart loses** all of it, and none of it is ever reconstructed from the
archive.

After a restart:

* payload discovery still works;
* the old preparation identifier is gone — its review route answers
  `404 PREPARATION_NOT_FOUND`, and confirming against it is refused;
* the archive still holds exactly the same three files.

Re-entering the *same* owner inputs produces the same profile, payload and
authority fingerprints, the same public confirmation message, and the same tag.
Confirming again replays the exact same archive idempotently: the bytes do not
change, no fourth file appears, and no receipt is created.

That replay demonstrates determinism for one exact authority. It does not
demonstrate fresh secret possession, it does not authenticate the actor, and it
adds no new execution or evaluation result.

---

## 17. Safe retry and cleanup

* **Extraction refused** — read the single `error=<CODE>` line. For
  `HISTORICAL_PAIRING_V4_OUTPUT_EXISTS`, inspect the existing file and delete it
  explicitly before retrying; never assume it is complete.
* **Startup refused with exit 3** — the single `error=<CODE>` line names the
  refusal. Nothing was created; fix the locator or the document and start again.
* **Confirmation refused** — a wrong tag answers `403 CONFIRMATION_REJECTED`,
  malformed tag syntax answers `400 CONFIRMATION_TAG_MALFORMED`, a missing
  dedicated header answers `400 CONFIRMATION_TAG_REQUIRED`, and a wrong expected
  fingerprint answers `409 STALE_AUTHORITY_FINGERPRINT`. None of them publishes
  anything. Start a new preparation if the authoring content must change.
* **Cleanup** — you own the wrapper, the standalone V4 document, the enablement
  document, the secret file and the exported confirmation message. Delete the
  exported confirmation message and any local copy of the tag when you are done.
  Keep the secret file only as long as you intend to confirm again; deleting it
  does not invalidate anything already archived.
* Stop the launcher with `Ctrl+C`. It closes its loopback sockets, drops every
  in-memory preparation, and touches neither the archive nor your configured
  documents.

---

## 18. Known limitations and non-claims

* `actor_id` is **asserted**, never authenticated.
* The tag is a symmetric shared-secret message authentication code. It is
  **not a signature**.
* The construction carries no nonce, so it is **deterministic and replayable**;
  acceptance does not prove fresh secret possession by whoever confirmed.
* Archive publication is **not an execution**, result, evidence, eligibility,
  obligation-satisfaction, claim-support, or verdict claim.
* The archive is **not a confirmation receipt**, and no read model may infer
  that a tag was presented from the archive's existence.
* **Restart loses** preparation, review and consumed state; it is never
  reconstructed from the archive.
* The derived V5 evaluation profile is deliberately non-launchable. It
  authorizes post-run evaluation only and authorizes no execution.
* The pairing authority document is intentionally public. Anyone holding it can
  reconstruct the public confirmation message; only the configured secret turns
  that message into a tag.
* Multiple distinct pairings may coexist for one historical payload. This
  workflow defines no revocation or supersession semantics.
* The lower-level historical evaluation store remains callable directly by
  trusted internal code without any confirmation. This workflow gates only what
  passes through it.
* Secrets are immutable Python bytes and browser strings once read. Dropping a
  reference is not zeroization, and none is claimed.
