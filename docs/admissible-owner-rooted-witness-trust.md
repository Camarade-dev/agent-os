# Owner-rooted Codex witness trust (canary repair)

## Scope and status

This document records the repair required by the independent anchored
model-binding audit, whose verdict was
`CANARY_MODEL_BINDING_TRUST_AUDIT_FAIL`. That audit accepted the closed canary
model policy, the real-binary witness, exact-byte intake, authority continuity,
terminal ordering, tests and packaging. It rejected three things:

1. the witness store created its own anchor, so an ordinary caller could build a
   completely fabricated but internally self-consistent store and obtain a
   verified receipt without executing Codex;
2. the future preflight manifest did not refuse additional files;
3. a copied preparation directory validated at another path.

The authorized canary tuple is unchanged: model `gpt-5.3-codex`, reasoning
effort `low`, `allowProviderModelFallback` false, pinned Codex SHA-256
`a2a05dafaa1acb002a45eaec0a462de5b13694fcfcd7bc43305f14781ce7be14`, protocol
schema identity
`cec0eb5631a013b3be09670f9aa05193b43cf47b9ad7443d6266fff8b7fe960f`, policy kind
`chatgpt_codex_canary_gpt_5_3_low_v1`. Exact-byte intake, protocol handling,
brokers, egress, verification and finalization are unchanged in design.

No owner authority was created or consumed for the future real canary. The
future real run remains absent.

## Why the previous anchor was not a trust root

The store anchor, run anchors, evidence packs, receipts and tail are all
produced by the store itself. Every one of them is a hash or nonce this
repository's own code generated. Detecting a *copied* or *rewound* store is a
real property of that construction, and it is retained; establishing that the
store deserves trust is not, and never was.

Concretely, the audit's attack is now a test
(`test_fully_fabricated_candidate_store_yields_no_production_authority`). It
mints a fresh store, writes a run anchor, an evidence pack, a receipt and a tail
that are mutually consistent and carry the correct expected model, executable,
namespace and terminal values, and never runs Codex. That store still loads as
candidate evidence, because nothing inside a store can distinguish it from a
genuine one. What it cannot do is produce an owner-bound receipt.

## Candidate versus owner-bound semantics

The objects are renamed so their semantics are honest:

| object | authority |
| --- | --- |
| `CandidateSerializationWitnessStore` | none |
| `CandidateSerializationWitnessPack` | none |
| `CandidateSerializationWitnessReceipt` | none |
| `CandidateEvidenceBundle` | none |
| `OwnerAuthorizationPayload` | none — it is a *request* |
| `OwnerBoundVerifiedSerializationReceipt` | production pre-effect authority |

Every document the store writes now carries
`trust_state: UNTRUSTED_CANDIDATE_REQUIRES_OWNER_BINDING`, and every validator
refuses a document that omits it. `evaluate_serialization_witness` reports both
`candidate_receipt: false` and `owner_bound_receipt: false`.

None of the following creates production authority by itself: creating a store;
creating its store anchor; executing public persistence functions; creating a
self-consistent pack, receipt and tail; loading a current receipt from a
caller-selected path; or knowing every expected model, executable and network
value.

`CandidateSerializationWitnessPack` is new and deliberate. The pack, not the
receipt, carries the real-binary evidence: the executable attestations taken
before and after the confined run, the namespace/network observation, the
captured request and the terminal result. `pack.revalidated()` re-checks all of
it independently of any receipt, so the trusted authorization path never has to
trust a summary.

## External owner trust-root schema

The external root is the owner. The digest construction is a versioned successor
to the one `admissible.delegated_gate.native_canary` already uses:

```
OWNER_DIGEST_CONSTRUCTION = "admissible_owner_phrase_nul_canonical_payload_sha256_v2"

digest = sha256(construction || 0x00 || phrase || 0x00 || canonical(payload_body))
```

The construction label is inside the hashed material, so a digest computed for
one construction can never satisfy another. No API key and no other user secret
is introduced.

The phrase arrives only on its dedicated descriptor.
`read_owner_phrase_from_descriptor` requires a pipe, a socket or a regular file
(which covers an anonymous `memfd`), refuses a terminal or character device,
bounds the read, and zeroes its buffer. The phrase is used for exactly one
`hmac.compare_digest` inside `owner_authorization.py` and is never returned,
logged, persisted, fingerprinted on its own, or handed to the general
controller, the witness store or the model backend. The regression
`test_no_owner_phrase_material_appears_in_the_owner_bound_receipt` asserts the
phrase text is absent from the receipt and that the only occurrence of the word
"phrase" is the construction label.

The expected digest is retained outside the preparation, in
`OwnerAuthorizationStateStore`, whose root must not be the preparation root or
inside it.

## Owner payload and authorization binding

`OwnerAuthorizationPayload` is a closed schema whose complete body is
fingerprinted. It canonically binds:

* the repository canonical path, repository HEAD and implementation HEAD;
* the run and preparation identities, which must equal the run and preparation
  inside the preparation-root identity;
* the preparation-root identity (path, device, inode, mode, type, IDs);
* the candidate store root identity, store-anchor fingerprint, evidence-pack
  fingerprint, receipt identity, witness-run identity, witness-run nonce and
  the exact current store tail;
* the model-binding policy and its fingerprint, the canonical configuration
  fingerprint, the executable identity and SHA-256, and the protocol schema
  identity;
* the boundary-launcher identity, destination-manifest identity, mission
  fingerprint, tool authority identity and explicit budgets;
* the preflight manifest fingerprint, the preflight seal fingerprint and the
  externally retained seal identity;
* the fixed zero-retry, zero-repair policy (`retries: 0`, `repairs: 0`,
  `launches_per_authorization: 1`).

The model policy inside the payload must be the closed canary policy;
`validated_canary()` refuses anything else.

## Trusted owner-bound receipt

`OwnerBoundVerifiedSerializationReceipt` binds the candidate receipt, the
complete durable pack, the owner payload fingerprint, the verified owner
authorization digest, the boundary-launcher identity, the preparation-root
identity, the exact current candidate tail, the model policy, the run identity
and a one-time authorization-consumption identity.

`authorize_owner_bound_serialization_receipt` is the only route to one, and it
performs the steps in order:

1. canonicalize the owner payload and check it against the retained state;
2. verify the owner phrase against the exact canonical payload bytes;
3. reopen the candidate store and its evidence pack;
4. independently revalidate every real-binary witness claim;
5. verify the current store tail is still the authorized one;
6. verify the fixed canary policy;
7. verify the preparation root and its closed-world seal;
8. verify the authorization is still unconsumed.

Python constructor privacy is not the security boundary. The boundary is that
every field is re-derived from reopened durable evidence plus an external digest
this code cannot compute without the phrase. The private construction token only
prevents an accidental in-process forgery, and there is a test for it.

## Production backend construction

Production `HostCodexAppServerCapsuleBackend` construction requires an
`OwnerBoundWitnessAuthority`: the owner-bound receipt, the external one-time
authorization state, the preparation root and the externally retained seal
identity. That gate is the outermost check in `__init__`, so an absent owner
binding refuses before anything else is inspected.

The removed routes are gone. There is no production path that accepts a witness
store alone, a candidate receipt alone, a store anchor minted by that store, or
a caller-selected witness path: in production the candidate receipt is *named by*
the owner-bound receipt, reloaded from the store, and required to equal the copy
the owner authorized, pack included.

`BackendExecutionAuthority` now carries `owner_binding_state`,
`owner_bound_receipt_identity`, `owner_payload_fingerprint` and
`owner_authorization_consumption_identity`. `create` refuses a production
connection mode without an owner-bound receipt, and `validated` refuses the same
combination when the authority is reloaded from durable evidence, so a
production execution authority cannot exist without an owner binding. The OS
boundary authority carries the same two-field owner binding, and a
non-production boundary may not claim an owner-bound receipt.

The backend refuses before preparing or executing an effect when the owner
binding is absent; targets another store, pack, policy, root or run; was already
consumed before this backend existed; when the candidate tail advanced after
authorization; when the preparation root changed; when candidate evidence
changed; or when a fresh fabricated store is substituted.

`NonProductionWitnessMode` is the explicitly separate synthetic/provider-free
development mode. It requires the acknowledgement
`NON_PRODUCTION_SYNTHETIC_DEVELOPMENT_CANDIDATE_EVIDENCE_NO_OWNER_BINDING`, is
impossible under a production connection mode, and never produces an owner-bound
receipt.

## Authorization ordering and one-time consumption

The rehearsed order is:

1. verify repository and preparation identity;
2. classify the local ChatGPT login from descriptor metadata only;
3. verify candidate witness evidence and the preflight seal;
4. request the owner phrase on its dedicated descriptor;
5. verify the exact canonical owner payload;
6. create the owner-bound witness receipt;
7. atomically consume the authorization;
8. start the single target Codex turn;
9. permit effects only after all model and receipt guards pass.

Consumption is a single `O_CREAT|O_EXCL` create under an exclusive `flock`, keyed
by the consumption identity. Deterministic local validation failures before step
4 refuse without consuming anything, because consumption is a separate explicit
call made by `prepare_workspace` after every local check has passed and before
the first effect. Within one launch, later pre-effect gates accept an
authorization consumed *by that backend*; a backend constructed against an
authorization consumed earlier refuses. Zero retries and zero repairs remain
mandatory after consumption.

`classify_local_chatgpt_login` opens the file `O_RDONLY|O_NOFOLLOW` purely to
`fstat` it and closes it without a single `read`. It reports file type, mode,
link count, owner UID and size, plus `credential_bytes_read: 0` and
`credential_content_observed: false`. No credential byte is read, copied,
displayed or hashed.

## Closed-world preflight manifest

The V2 manifest now represents the complete authorized preparation tree.
`observe_preparation_tree` enumerates every entry beneath the root recursively
and refuses symlinks, hardlinks, special entries, path/case/Unicode aliases and
unbounded trees. Coverage is derived from that observation, never from a
caller-supplied path list, so an operator cannot leave a file out.

The manifest records, for every covered file, the normalized relative path,
entry type, mode, size and SHA-256, plus an explicit expected-directory set with
paths, types and modes. Only `evidence/content-manifest-v2.json` and
`evidence/preflight-seal-v2.json` are excluded from coverage, and there is no
ignore rule: `extra_entry_policy` is `REFUSE_ANY_UNLISTED_ENTRY`.

Validation observes the complete tree before ruling and refuses an added file
anywhere, an added directory, a removed entry, an unexpected empty directory, a
renamed entry, a path/case/Unicode alias, and mutation observed during
validation (the tree is enumerated again at the end and must be identical).
Neither document contains its own final-byte hash, so the construction remains
non-self-referential.

## Preparation-root binding

`preparation_root_identity` binds the canonical absolute path, device, inode,
root mode, root type, preparation ID and run ID, and the seal, the manifest and
the retained identity all carry it. Validating a byte-identical copied directory
at another path or inode refuses with
`future preflight preparation root was copied, moved or re-created`.

For the first canary, portability is not required. A new location requires a new
preparation and a new owner authorization.

## External seal retention

`RetainedPreparationSealIdentity` holds the expected manifest fingerprint and
the expected seal fingerprint outside the preparation directory, and the owner
payload binds its `retained_identity`. Both `publish` and `load` refuse a
retention path equal to or inside the preparation root, so the preparation
cannot mint both a replacement seal and the expected fingerprint used to
validate it. Replacing the manifest and the seal with a mutually consistent pair
still fails, because the replacement's fingerprint is not the retained one.

The classifications are:

* `SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION` before owner authorization;
* `OWNER_BOUND_READY_FOR_SINGLE_LAUNCH` after authorization and receipt
  creation;
* `OWNER_AUTHORIZATION_CONSUMED` after consumption.

No earlier state is runnable: the backend refuses any classification other than
`OWNER_BOUND_READY_FOR_SINGLE_LAUNCH` at construction.

## Provider-free rehearsal

`tests/test_admissible_capsule_owner_bound_rehearsal.py` rehearses the whole
order with synthetic authentication and no public endpoint: candidate witness
evidence created through the real pinned Codex binary in a private routeless
namespace, a closed-world preparation manifest, the external retained seal
identity, the canonical owner payload, a synthetic owner phrase delivered on a
dedicated pipe descriptor, the owner-bound receipt, one atomic consumption, the
synthetic one-write canary, intake, both verifiers, finalization, and proof that
a second launch on the same authorization refuses with
`OWNER_AUTHORIZATION_ALREADY_CONSUMED`. It creates and consumes no real canary
authorization.

## Remaining real-canary-only unknowns

* whether a real ChatGPT account is entitled to `gpt-5.3-codex`;
* what model the real service ultimately selects and reports;
* whether the real service honours `low` reasoning effort end to end;
* whether the destination manifest is complete for a real authenticated turn;
* whether a real login can refresh inside the sealed boundary;
* whether the real owner phrase, entered once on its dedicated descriptor,
  matches the digest retained for the real payload.

None of these are claimed by this repair. Historical V1 preparations,
`canary-preflight-v1`, historical runs, owner-preflight trees, external spikes
and the detached audit worktrees are not authorities for this repair and are not
modified by it.
