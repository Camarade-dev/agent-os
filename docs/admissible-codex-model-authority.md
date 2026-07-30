# Codex model and reasoning-effort authority (canary repair)

## Scope and status

This document records the narrow production repair required by the first
failed ChatGPT Codex canary preflight, whose terminal verdict was
`CHATGPT_CODEX_CANARY_MODEL_UNRESOLVED`. That preflight established that the
production surface carried no explicit model or reasoning effort through Codex
argv, the ephemeral `CODEX_HOME` configuration, `thread/start`, `turn/start` or
the execution authority. It created and consumed no owner authority, and the
future real run remains absent.

The repair now has four narrowly coupled pieces:

1. a canonical immutable mission/run **model-binding policy**;
2. a durable **candidate serialization-witness receipt** and evidence pack,
   which are untrusted on their own (see
   [owner-rooted witness trust](admissible-owner-rooted-witness-trust.md));
3. a model authority derived only by reopening that receipt and its complete
   evidence pack;
4. the already proven optional closed **exact-material policy** in
   `CanonicalIntake`.

The independently audited OS boundary, brokers, egress, controller, capsule,
verification and finalizer are unchanged in design.

## The exact channel proven from pinned Codex 0.145.0

Everything below was determined from the content-pinned
`codex-cli 0.145.0` executable
(`packages/standalone/releases/0.145.0-x86_64-unknown-linux-musl/bin/codex`),
its generated app-server JSON Schemas, its `--strict-config` oracle and its
provider-free request serialization against a loopback synthetic endpoint. The
mutable `codex` symlink is never used as the authority: it currently resolves
to a `0.146.0` release, and `ExecutableFileIdentity` refuses any path with a
symlinked component.

| Layer | Field | Behaviour in 0.145.0 |
| --- | --- | --- |
| `v2/ThreadStartParams.json` | `model` (`string \| null`) | authoritative for the thread |
| `v2/ThreadStartParams.json` | `allowProviderModelFallback` (`boolean`) | bound to `false` |
| `v2/ThreadStartParams.json` | `config` overlay | carries `model` and `model_reasoning_effort`; **no** reasoning-effort property exists on `ThreadStartParams` itself |
| `v2/TurnStartParams.json` | `model` (`string \| null`), `effort` (`ReasoningEffort`) | re-assert the same two values per turn |
| `v2/ThreadStartResponse.json` | `model`, `reasoningEffort` | the *effective configured* values, observable before any effect |
| ephemeral `CODEX_HOME/config.toml` | `model`, `model_reasoning_effort` | recognized by `--strict-config`; authoritative when the request fields are absent |

With the model and effort removed from **every** layer, pinned 0.145.0 starts
the thread on its own mutable client default (observed: `gpt-5.6-sol`) and
serializes that default onto the request. Denying that fallback is the entire
point of the binding, so the repair writes both values in both layers.

`--strict-config` is deliberately *not* added to the Codex argv. Pinned 0.145.0
applies the flag to the `thread/start` configuration overlay as well, and the
audited preventive control overlay legitimately carries feature keys this build
does not recognize (`features.skills`, `features.apps`, …), so the flag would
refuse the existing production thread. Configuration override is instead denied
structurally: no `-c`/`--config` argument is ever passed, the mount namespace is
empty, `HOME` and `CODEX_HOME` both point at the broker-owned ephemeral home,
and the effective configuration bytes are re-attested immediately before Codex
starts.

## Canary binding

```
configured model                     gpt-5.3-codex
configured reasoning effort          low
serialized model                     gpt-5.3-codex
serialized reasoning effort          low
provider model fallback              refused
```

`auto`, an omitted value, a mutable client default, a fallback model, `xhigh`
and any provider-selected model without prior request binding are all refused
by construction: `require_exact_model` and `require_exact_reasoning_effort`
reject non-lowercase tokens, padded tokens, the prohibited value set
(`""`, `auto`, `default`, `none`, `null`) and anything outside the closed
reasoning-effort vocabulary (`low`, `medium`, `high`).

## What is bound

`ModelBindingPolicy` binds, canonically and immutably:

* the configured model and configured reasoning effort;
* `allowProviderModelFallback = false`;
* the exact configuration channel identifier;
* the exact `thread/start` and `turn/start` request fields;
* the exact canonical ephemeral configuration bytes, their size and SHA-256;
* the configuration fingerprint;
* the pinned Codex executable identity;
* the app-server protocol version and generated-schema identity;
* the provider-free observation-policy identity and trusted verifier identity;
* the explicit prohibition record.

The canary instance is closed to `gpt-5.3-codex`, `low`, fallback false, Codex
0.145.0 with executable SHA-256
`a2a05dafaa1acb002a45eaec0a462de5b13694fcfcd7bc43305f14781ce7be14`,
and protocol-schema identity
`cec0eb5631a013b3be09670f9aa05193b43cf47b9ad7443d6266fff8b7fe960f`.
A future mission can seal another explicit policy, but it cannot inject that
policy through the canary backend.

`SerializationWitnessRecord` and its fingerprint are explicitly untrusted
observations. `CodexModelAuthority.create` produces only an
`ISOLATED_UNAUTHORIZED` object suitable for protocol/configuration analysis.
It is never launch authority. A launchable model authority is derived only
from an opaque verified receipt and a simultaneous reopen of its durable pack
through the trusted store. Serialized authority bytes lose this live
provenance and cannot restore it.

`BackendExecutionAuthority` (schema `…_execution_authority_v5`) carries the
complete policy, receipt metadata, receipt/run identities, model authority and
all fingerprints. Its creation reopens the durable evidence again. Changing
the model, effort, executable, protocol schema, verifier, receipt, or run
changes the dependent OS-boundary authority, protocol-request policy, backend
execution authority and bubblewrap launch fingerprint.

`HostCodexAppServerCapsuleBackend` has no optional model-authority, model, or
effort parameter. It obtains the path-bound candidate witness store only from
the bound session trust root, constructs the one canary policy from the
content-attested executable, and derives the authority. A valid-in-isolation
authority for another model or for `medium`/`high` is therefore irrelevant to
backend construction.

The candidate receipt is not by itself sufficient. Production construction
requires an `OwnerBoundVerifiedSerializationReceipt` that names this exact
store, pack, receipt, tail, policy, preparation root and run, plus its one-time
authorization state. See
[owner-rooted witness trust](admissible-owner-rooted-witness-trust.md).

## Launch channel

1. The authentication broker generates the ephemeral home. Authentication
   contents arrive only by descriptor and are written to `auth.json`; the
   non-secret canonical configuration bytes are written separately to
   `config.toml`.
2. `PREPARE` evidence returns a `configuration_identity`
   (`filename`, `size`, `sha256`, `contains_authentication: false`) and nothing
   else about the configuration. The general controller may know that identity;
   it never sees authentication contents or any source pathname.
3. `CodexConfinementLaunchPolicy` re-reads `config.toml` through the held home
   directory descriptor and re-attests it byte-for-byte against the model
   authority immediately before Codex starts. `auth.json` is never opened there.
4. The launch policy record embeds the model authority fingerprint, the
   configuration fingerprint, the configured model, the configured effort and
   the effective configuration identity, so the launch fingerprint changes with
   the binding.

## Runtime enforcement

Before preparation, launch, and every dynamic effect guard, the backend
reopens the receipt, run anchor, external tail, and exact evidence pack. It
then checks policy/authority/receipt/run/executable continuity.
`_run_protocol` validates `ThreadStartResponse.model` and
`ThreadStartResponse.reasoningEffort` against the bound authority *before*
`turn/start` and therefore before any dynamic tool call. The validated binding
is recorded on the backend, and every `item/tool/call` re-checks it through
`_require_validated_model_configuration` before an effect can reach the capsule.
A configuration or protocol mismatch terminates the session with
`APP_SERVER_PROTOCOL_FAILED`, with no recorded tool request and no capsule
effect.

## Configured versus effective versus real

Three distinct claims are kept distinct, and the evidence names them:

* **configured model / effort** — what the authority binds and what the
  ephemeral configuration and request fields carry.
* **provider-free serialized model / effort** — what the real pinned client put
  on the wire against a loopback synthetic endpoint.
* **real service-selected model** — recorded as
  `CANARY_TIME_OBSERVATION_ONLY`. Offline serialization does **not** prove
  entitlement, and it does not prove final provider routing.

## Trusted provider-free serialization witness

`admissible.capsule.serialization_witness` owns the parent verifier, store and
receipt schemas; its confined child is
`admissible.capsule.serialization_witness_runtime`. The trusted path runs the real pinned
0.145.0 binary with synthetic authentication inside a private routeless
network namespace whose only interface is loopback, against a local synthetic
ChatGPT-compatible `/v1/responses` endpoint that answers every request with a
terminal stream failure. No public DNS name, no public endpoint, and no real
model or provider execution is involved.

Only three request values are captured: the request path, the serialized
`model` and the serialized `reasoning.effort`. Prompt contents, request input
items, instructions, synthetic token contents, HTTP authorization, unrelated
headers and response bodies are never recorded.

**Transport limitation, recorded rather than implied away.** Pinned Codex
0.145.0 compiles its TLS trust anchors in. It ignores `SSL_CERT_FILE`,
`SSL_CERT_DIR`, `CODEX_CA_CERT` and `NODE_EXTRA_CA_CERTS`, and 0.145.0 accepts
no configuration key for an additional certificate authority (`extra_ca_certs`,
`ca_bundle_path`, `tls_ca_file`, `danger_accept_invalid_certs` and a `[tls]`
table are all rejected as unknown fields). A synthetic TLS certificate
therefore cannot be trusted by the real client, so the witness endpoint is
cleartext on loopback inside the private namespace. The sealed egress
architecture is unchanged and still refuses every destination outside its
manifest; it never terminates TLS.

Before execution the trusted store publishes one run anchor binding a random
run identity/nonce, sequence, previous tail, store anchor, verifier, policy,
configuration and executable identities. After the terminal local refusal it
atomically publishes and fsyncs the complete evidence pack, reads it back,
publishes a receipt and advances the single-writer tail. Loading reopens every
object and recomputes every identity. The store anchor is bound to the exact
canonical path and directory device/inode, and its reference is sealed outside
the mutable session journal. A copied directory or self-consistent hash chain
under an unauthorized path does not acquire authority.

The receipt binds the witness schema/run/nonce; executable content and
before/after stat identity; protocol and configuration identities; configured,
serialized and effective model/effort; fallback false; request path;
namespace/no-route/no-resolver evidence; local endpoint policy; exact process
terminal result; captured-request and full-pack fingerprints; verifier
identity; and durability-receipt identity. It contains no prompt, synthetic
credential, authorization header, or response body.

The witness fails for `auto`, an omitted model, another model, changed model
casing, an omitted effort, `medium`/`high`/`xhigh` effort, a substituted
ephemeral configuration, executable, network evidence, run nonce, pack,
receipt, tail or store. Fixed synthetic credentials, endpoint fixtures,
certificates, keys, and test drivers are excluded from both distributions.
The shipped verifier generates its credential and loopback port per run.

## Future preflight sealing

Historical `canary-preflight-v1` is never opened for writing and remains an
unconsumed model-unbound preparation. Future V2 preparations use an immutable
content manifest that excludes both publication files. A separate final seal
binds the exact manifest bytes, size, SHA-256 and fingerprint plus the model
policy and witness receipt/run. The externally retained seal fingerprint is
required when reloading. Thus neither document claims to contain its own final
byte hash; content mutation, manifest mutation, and seal mutation are each
detected.

## Optional exact-byte canonical intake

`IntakeAuthority` gains an optional closed `exact_material` policy. For each
exact-authorized file it binds the normalized relative path, the exact
regular-file mode, the exact byte size and the exact SHA-256. The policy is
canonical and immutable, is included in the intake-authority fingerprint when
present, and is reconstructed from durable evidence by `from_dict`.

Missions that authorize paths and bounds without fixed bytes are unaffected:
when the policy is empty the key is omitted from the authority body, so those
authorities keep their previous fingerprints byte-for-byte.

Wrong bytes, wrong size or wrong mode are accumulated during the complete
observation as `EXACT_BYTES_MISMATCH`, `EXACT_SIZE_MISMATCH` and
`EXACT_MODE_MISMATCH`, so intake itself rules `REJECTED` and never reaches
`ACCEPTED_INTAKE_PUBLISHED`. Those cases are not deferred to checkpoint or
behavioral verification. The re-confirmation read before publication also
re-checks the exact policy, so a source swapped after observation is caught as
`SOURCE_MUTATED`. Complete observation, race defenses, publication states and
accepted-material identity are otherwise unchanged.

The canary fixture is:

```
path   CANARY.txt
mode   100644
bytes  admissible-chatgpt-codex-canary-v1\n
```

Its size and SHA-256 are computed programmatically by
`ExactMaterialRecord.for_bytes`, both in the authority construction and in the
tests; no digest is hand-entered anywhere.

## Remaining real-canary-only unknowns

* whether a real ChatGPT account is entitled to `gpt-5.3-codex`;
* what model the real service ultimately selects and reports;
* whether the real service honours `low` reasoning effort end to end;
* whether the destination manifest is complete for a real authenticated turn;
* whether a real login can refresh inside the sealed boundary.

None of these are claimed by this repair.
