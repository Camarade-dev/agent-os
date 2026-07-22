# ADR: Claim-Aware Authority Evolution for Admissible

- **Status:** Accepted for the immediate visibility slice; architectural direction accepted subject to staged implementation.
- **Date:** 2026-07-22
- **Repository baseline:** `eee96201e69f3c022311912665f68570457bf913`
- **Submission baseline audited independently:** `cade45f6e1d8b411d7bebeeafd6116ffa152f3fd`

## Context

Admissible currently has a strong runtime-v2 authority chain for bounded native execution:

- canonical mission profiles;
- owner-bound authorization;
- workspace, Git, process, budget, and backend constraints;
- persisted evidence;
- evidence-only reconstruction;
- authoritative product verdicts;
- human disposition kept separate from machine authority.

However, semantic result claims remain governed only at a coarse, run-global level.

The current runtime-v2 profile contains `gate_clauses`. These clauses are created by the launcher template, included in the profile fingerprint and therefore in the owner authorization identity, rendered to the execution provider, not surfaced clearly to the owner, and not individually adjudicated. The product may nevertheless display `ADMITTED_VERIFIED`, creating an epistemic overclaim risk.

The repository also contains a separate historical lane with acceptance ledgers, criterion-level verification dispositions, runtime observability gaps, and coverage reports. Those concepts are informative, but their heuristic implementation is not part of the runtime-v2 authority chain and must not be imported as authority without redesign.

## Decision

### 1. Immediate repair: surface existing gate clauses

Before adding new claim schemas, Admissible will expose the existing authorized `gate_clauses`:

- in the authored contract summary;
- in the pre-authorization contract review;
- in the result view.

They must be displayed in canonical order with their IDs and text.

The product must state:

> These clauses are part of the authorized contract. They are not independently adjudicated unless linked to explicit verification evidence.

This change is presentation-only. It must not modify schemas, fingerprints, authorization digests, execution, verification, verdict derivation, or historical reconstruction.

### 2. `NativeMissionProfile` remains the root authority object

The future claim-aware architecture will extend `NativeMissionProfile`; it will not introduce a competing top-level mission authority.

```text
NativeMissionProfile V3
├── WorkspaceSourceAuthority
├── GitEndStatePolicy
├── VerificationAuthority
├── RuntimePromptAuthority
└── ClaimAuthority
    ├── authorship
    ├── claims
    ├── verification obligations
    └── result-policy identifier
```

### 3. `VerificationAuthority` remains intact

The existing global `VerificationAuthority` is load-bearing for runtime-v2 compatibility and remains unchanged through the first claim-aware slices.

Per-claim verification obligations will sit beside it under `ClaimAuthority`; they will not replace or overload it.

### 4. Claim authorship must be explicit

Initial admissible authorship classes:

- `OWNER_AUTHORED`
- `TEMPLATE_AUTHORED`

A future `MODEL_PROPOSED_OWNER_CONFIRMED` mode may be introduced only with an explicit owner-confirmation boundary. No implicit or unlabelled generated authorship is permitted.

### 5. Claim-set completeness is separate from claim adjudication

The architecture must keep separate:

- claim-set authorship;
- mission-to-claim coverage;
- per-claim adjudication.

A future claim-aware result must not present strong global assurance when mandatory mission requirements are absent from the authorized claim set.

### 6. Claim judgments are multidimensional

Admissible will not use a single monolithic epistemic or assurance enum.

```text
support_status:
  SUPPORTED
  REFUTED
  UNRESOLVED
  CONFLICTED

adjudication_status:
  ADJUDICATED
  NOT_ATTEMPTED
  AUTHORITY_UNAVAILABLE
  OBSERVABILITY_GAP

evidence_method:
  SELF_REPORT
  OBSERVATION
  AUTOMATED_CHECK
  HUMAN_RUBRIC
  PROOF

independence:
  temporal
  artifact
  process
  information
  model
  organizational

evidence_integrity:
  COMPLETE
  INCOMPLETE
  INCONSISTENT

plus:
  actual_coverage
  authority_reference
  evidence_references
  limitations
```

`evidence_integrity` should reuse or align with the existing completeness vocabulary rather than create a contradictory duplicate.

### 7. Verifier disclosure is a first-class limitation

A future verification obligation must record whether the subject was shown the oracle or verifier. Verifier identity and immutability do not imply semantic completeness, information independence, resistance to test-specific optimization, or broad coverage.

### 8. Human judgment evidence and owner disposition remain separate

A human may provide bounded evidence under a rubric. An owner may accept or reject a result despite known defects or unresolved claims. Owner disposition must never rewrite a claim judgment.

### 9. Product read model remains presentation-only

The product read model may display claim authorities and judgments. It must not become the derivation authority.

### 10. Historical evidence remains historically stable

Claim-aware outcomes require a new versioned schema. Existing runs must reconstruct forever under their original rules. No new claim ledger may be synthesized for historical runs and presented as if it had been authorized at execution time.

### 11. Do not begin with automatic oracle synthesis

The first usable claim-aware slice will support manually authored claims, manually authorized verification obligations, evidence already produced by existing runtime paths, and non-admitting claim judgments.

## Staged migration

### Step 1 — Authorized clause visibility

Presentation-only. No authority or schema change.

### Step 2 — Inert `ClaimAuthority`

Add optional, embedded, owner-visible, fingerprinted claims. No verdict change.

### Step 3 — Non-admitting claim judgments

Map existing authorized evidence to manually authorized obligations. Persist judgments in a new write-once sidecar. No global verdict change.

### Step 4 — Versioned claim-aware result admission

Introduce a new outcome schema and derive result admission from mandatory claim judgments while preserving historical runtime-v2 semantics.

## Acceptance criteria for the immediate slice

1. Gate clauses appear in the authored contract summary.
2. Gate clauses appear before authorization.
3. Gate clauses appear in the authoritative result presentation.
4. IDs, text, and order are preserved.
5. The non-adjudication notice is visible.
6. Historical or malformed evidence does not fabricate clauses.
7. Clause content is escaped safely.
8. Long clause text does not break the UI layout.
9. Product verdicts and verification modes remain semantically unchanged.
10. No schema, fingerprint, authorization, execution, or reconstruction authority changes are introduced.
