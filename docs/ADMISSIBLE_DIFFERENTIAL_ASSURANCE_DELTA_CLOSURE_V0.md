# Admissible — Differential Assurance Delta Closure V0

**Date:** 2026-08-09  
**Status:** `OWNER_ACCEPTED_ARCHITECTURE_PARK_CLOSURE`  
**Decision:** `PARK`  
**Confidence:** `HIGH`  
**Active Admissible build:** `NONE`  
**Active Admissible research question:** `NONE`

This document records the final bounded direction decision after the Admissible
Differential Assurance Audit and its stronger delta kill-test. It is a
repository-facing disposition layer. It does not rewrite the owner-adopted
post-literature thesis, the accepted NQI records, the SV-01 closure, or the M2
implementation history.

## 1. What is parked

The following are parked as required new program directions:

- Admissible as a required new general assurance architecture;
- M2 as a necessary substrate for global authoritative-progress safety;
- a new M3 selected merely as continuation of M2;
- the proposed M2 implementation replacement test;
- a large autonomous industrial E2E Admissible build justified by the current
  evidence.

No current work is authorized by this closure to restart those paths.

`PARK` is an investment disposition, not a theorem that the originating problem
is false or unimportant.

## 2. What remains open

The originating engineering problem remains real and open:

> How can long-running, complex agentic workflows automate useful work while
> ordinary faults in an agentic component fail closed rather than becoming
> prohibited authoritative progress?

The desired distinction remains useful:

```text
AGENT CLAIM != SYSTEM FACT
AGENT DONE != AUTHORITATIVE COMPLETION
CAPABILITY != AUTHORITY
LOCAL SUCCESS != GLOBAL AUTHORITATIVE PROGRESS
```

What is no longer established is that solving that problem requires a distinct,
large Admissible architecture or the retained M2 process-lifecycle machinery.

`INDUSTRIAL_SYSTEM_VALUE != RESEARCH_NOVELTY`

and, after this closure:

`ORIGINATING_PROBLEM_VALUE != ADMISSIBLE_ARCHITECTURE_NECESSITY`

## 3. Why the broad architecture is parked

The first differential audit rejected a broad `GO` but left a narrow `PIVOT`
around the candidate → execution → evidence → audit → publication chain.

A second bounded delta kill-test then challenged that residual wedge against a
stronger no-M2 composition using contemporary mechanisms for:

- claim/evidence/lifecycle gating;
- canonical action and approval-to-execution identity;
- durable signed workflow lineage and workload identity;
- disposable, capability-separated execution domains;
- independent candidate-bound verification;
- protected-branch checks and separately credentialed publication;
- expected-state remote Git publication;
- authoritative effect-boundary settlement for ambiguous external effects.

The resulting disposition was:

`PARK — HIGH`

The stronger composition removed the architectural necessity previously
attributed to M2. It does not imply that the composition is a turnkey product or
that every deployment is already independently qualified. It establishes only
that the current evidence does not justify building a new large Admissible
assurance architecture as the necessary solution.

## 4. Strongest no-M2 trust chain

The accepted kill-test model was approximately:

```text
untrusted builder
→ content-addressed immutable Git candidate
→ state-bound evidence manifest
→ canonical action / approval-to-dispatch identity
→ durable signed workflow lineage
→ disposable isolated credential-free execution domain
→ destroy/revoke execution domain
→ fresh independently identified verifier
→ candidate-bound required check / attestation
→ protected branch / serialized merge boundary
→ separately credentialed publisher
→ exact-source expected-state publication
→ authoritative remote readback
```

For privileged effects outside Git, the corresponding effect boundary must own
its own settlement truth. It must expose an adequate idempotency/query/receipt
contract or the workflow must remain `UNKNOWN/BLOCK` rather than manufacturing
success.

## 5. M2 necessity disposition

M2 remains a substantial implementation and evidence asset. This closure does
not diminish its engineering depth. It changes only the claim of necessity.

The accepted disposition of the major mechanism families is:

| M2 mechanism | Current disposition |
| --- | --- |
| Capsule/runtime/workspace identity | `REPLACEABLE` for the global property under the strongest no-M2 architecture |
| Private mount namespace / transactional export | `REPLACEABLE` |
| Membership-before-exec / per-effect cgroups / resource bounds | `REPLACEABLE` for authoritative-progress safety under disposable capability-separated execution |
| Exact PID ownership / subreaper / kill / reap / quiescence | `REPLACEABLE` under that architecture |
| Cleanup-obligation registry / exact cgroup removal / bounded drain | `CONDITIONAL` — safety-relevant in shared or credentialed runners, otherwise primarily runner hygiene |
| Effect ledger / typed reconciliation / local retry paths | `REPLACEABLE` at the general workflow level by durable state-bound mechanisms; external truth still belongs to the effect boundary |
| Local Git expected-state CAS | `REPLACEABLE` by the authoritative remote publication boundary |
| Independent audit → remote publication binding | `NOT_ESTABLISHED` in M2 |
| External lost-ack / duplicate-effect settlement | `NOT_ESTABLISHED` in M2 and must be solved by the external effect boundary |

Therefore:

`NO_MAJOR_M2_MECHANISM_ESTABLISHED_NECESSARY_UNDER_STRONGEST_NO_M2_ARCHITECTURE`

This does not claim that M2 is useless. M2 remains a reusable high-assurance
runner-containment, cleanup, fault-injection and forensic component for systems
whose chosen execution architecture keeps a shared mutable or credentialed
runner inside the relevant authority path.

## 6. Residual lost-ack case

The strongest residual fault considered was:

```text
external operation E submitted with stable key K
→ external boundary commits E
→ acknowledgement is lost
→ consumer crashes before durable local completion
→ recovery cannot know whether E committed
→ retry may duplicate E
```

Destroying the worker does not reconstruct the result. M2 process ownership and
cleanup machinery do not reconstruct it either.

The correct closure remains at the authoritative effect boundary:

- query/deduplicate by stable operation identity when supported;
- return the already committed result when known;
- otherwise preserve an explicit uncertain state and block unsafe retry.

This is consistent with the accepted post-NQI boundary: orchestration must not
manufacture physical or external commit truth.

## 7. Current program state

As of this closure:

```text
ADMISSIBLE_RESEARCH = CLOSED
ADMISSIBLE_REQUIRED_NEW_ASSURANCE_ARCHITECTURE = PARKED
M2_NECESSITY_HYPOTHESIS = CLOSED_NOT_ESTABLISHED
M2_IMPLEMENTATION_REPLACEMENT_TEST = WITHDRAWN
ACTIVE_M3 = NONE
ACTIVE_ADMISSIBLE_BUILD = NONE
ACTIVE_ADMISSIBLE_RESEARCH_QUESTION = NONE
ORIGINATING_HIGH_ASSURANCE_AGENTIC_WORKFLOW_PROBLEM = OPEN
```

A future Admissible build may be reopened only by new concrete evidence that
changes this investment disposition, for example a fault class that materially
survives the strongest existing composition and for which a retained Admissible
mechanism is actually necessary.

Project momentum, sunk cost, M2 complexity, or the existence of an unimplemented
next milestone are not reopening evidence.

## 8. Hard non-claims

This closure does not claim:

- that the originating high-assurance workflow problem is solved turnkey;
- that no useful Admissible product could ever exist;
- that M2 has no reusable engineering value;
- that the strongest no-M2 composition has received integrated independent
  production qualification;
- that agentic assurance is a solved field;
- that the absence of established Admissible necessity proves impossibility of
  future differentiated value;
- production readiness;
- research novelty;
- benchmark superiority.

The decision is narrower:

> The information available at the 2026-08-09 cutoff does not justify further
> major investment in Admissible/M2 as a required new assurance architecture.

That is the terminal disposition for the current program unless separately
reopened by new evidence.
