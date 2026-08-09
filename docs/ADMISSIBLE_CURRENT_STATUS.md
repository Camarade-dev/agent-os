# Admissible — Current Thesis and Program Status

**Status:** `CURRENT_CANONICAL_REPOSITORY_ENTRY_POINT`  
**Research program:** `STOPPED_FOR_CURRENT_PROGRAM_PURPOSES`  
**Industrial/system program:** `OPEN_AND_SEPARATE_FROM_RESEARCH_NOVELTY`

This document is the repository entry point for the current Admissible thesis,
research status, and document hierarchy. It does not rewrite historical
artefacts. Where a registered object was adopted or externally accepted, that
object remains the authority for the historical decision.

## 1. Current system framing

The following framing remains valid as product/system shorthand:

> **The model proposes. Admissible authorizes.**

and:

> **The model decides what could be done. Admissible decides what may be done.**

These are **not research-novelty claims**.

The post-NQI architectural boundary is:

```text
model / planner
→ proposes action
→ Admissible
→ checks authority/evidence/policy and the effect contract it has been given
→ authorizes, refuses, or asks for evidence/authority
→ effect boundary
→ owns the physical commit semantics it is actually capable of owning
→ returns grounded effect evidence/status when available
```

Admissible governance must not be described as creating authoritative physical
commit truth merely by keeping more history or moving settlement state into the
orchestration layer.

## 2. Adopted research-thesis baseline

The owner-adopted post-literature thesis is V0.6.

- registered package: `ADMISSIBLE_POST_LITERATURE_THESIS_V0.6_OWNER_ADOPTED_REGISTERED.zip`
- registered package SHA-256: `7960b0750c2c42fe86c02d5b0b61e60189e938386714c85ec273ae366f4bb1a0`
- adoption status: `POST_LITERATURE_RESEARCH_THESIS_V0_6_ADOPTED_BY_OWNER`
- operative disposition SHA-256: `0447b9ea3eefa3df968618330f1c15a1ae609dea99717c169e4d9cb0dc4081e5`
- operative delta SHA-256: `6190479e92d9476209feca82044d5c0eb1abd611122aacea8ca9e68ccc36306f`

The byte-identical operative disposition is preserved at
[`research/ADMISSIBLE_POST_LITERATURE_THESIS_V0.6.md`](research/ADMISSIBLE_POST_LITERATURE_THESIS_V0.6.md).
Its internal header still says `CANDIDATE ... NOT ADOPTED` because those bytes
are the immutable object that was subsequently adopted. The adoption record,
not a silent rewrite of those bytes, changes its status.

The adopted disposition:

- retains the proposal/authorization distinction as product/system framing;
- withdraws semantic admission as a distinctive architectural primitive;
- treats semantic admission/task-action alignment/authorization/runtime
  governance as occupied or partially occupied mechanism space, not empty space;
- narrows residual M2 continuity/effect machinery to
  `CONDITIONAL_CANDIDATE_EXPERIMENTAL_APPARATUS`;
- retains physically justified scored→executed/effect identity as an
  experimental-validity requirement, not Admissible novelty;
- rejects `raw/frontier agent vs Admissible` as a sufficient serious primary
  scientific comparison;
- retains only a bounded empirical incremental-value hypothesis, explicitly
  allowed to return **NO**;
- keeps industrial/system value separate from research novelty.

## 3. What NQI changed

The accepted NQI01–NQI05 chain did not establish an Admissible-specific
continuity primitive. It progressively localized the surviving hard
settlement property to the physical effect boundary.

The canonical repository-facing synthesis is
[`research/ADMISSIBLE_POST_NQI05_SYNTHESIS.md`](research/ADMISSIBLE_POST_NQI05_SYNTHESIS.md).

Residual M2 continuity/effect machinery remains:

`CONDITIONAL_CANDIDATE_EXPERIMENTAL_APPARATUS`

M2 may be useful where a selected experiment genuinely requires physically
justified scored→executed/effect identity. Sunk cost, implementation depth, or
engineering difficulty are not evidence that M2 is a necessary research or
security primitive.

The M2 implementation/qualification branch remains separate from `master`.
This documentation closure does not merge, cherry-pick, or promote that branch.

## 4. Final research status

SV-01 was the later attempt to determine whether an integrated Admissible
configuration was materially distinct enough from strong contemporary
comparators to justify a value benchmark.

It stopped **prebenchmark**. Both the initial G0 and the single authorized
bounded rerun ended externally at:

`G0-T0 — SV01_TREATMENT_DISTINCTNESS_INVALID_OR_UNRESOLVED`

The required treatment-distinctness gate did not pass. The benchmark was not
frozen and was not executed. Neither treatment distinctness nor clean treatment
non-distinctness was established.

The exact research closure is summarized in
[`research/ADMISSIBLE_RESEARCH_CLOSURE.md`](research/ADMISSIBLE_RESEARCH_CLOSURE.md).

Current owner disposition for this repository closure:

- the dedicated novelty research phase is stopped for current program purposes;
- no SV-01 rerun, substitute benchmark, M3 selection, long-running workload
  selection, or new novelty question is part of this work;
- a future research program would require a separate owner decision and a fresh
  evidence/protocol chain rather than inheriting SV-01 eligibility.

## 5. Industrial/system status

`INDUSTRIAL_SYSTEM_VALUE != RESEARCH_NOVELTY`

The industrial/system direction remains open and unrefuted by the research
program. A long-running system may still be valuable if proposal, authority,
effect, evidence, continuation, repair, and owner-intervention semantics remain
coherent under real complexity.

This does **not** establish production readiness, deployment fitness, or
benchmark superiority.

## 6. Publicly demonstrated surface

The bounded public demonstration is
[`public/ADMISSIBLE_PUBLIC_CANONICAL_DEMO_V0.1.md`](public/ADMISSIBLE_PUBLIC_CANONICAL_DEMO_V0.1.md).

The Demo/Portfolio program was explicitly closed after publication:

- closure package: `ADMISSIBLE_DEMO_PORTFOLIO_PROGRAM_OWNER_CLOSED_REGISTERED.zip`
- closure package SHA-256: `c3c3dbe0267b3cdbe7dcf976c3ae9e6866f3d18c5ceb22674887f273be995f01`
- terminal: `DEMO_PORTFOLIO_PROGRAM_CLOSED__PUBLIC_CANONICAL_DEMO_PUBLISHED`
- publication commit: `49e5f5cc61f1e5c9714d6d1576934946dfc5c326`

Its published content SHA-256 is:

`6e2cdea07a5a5cd4855d115c4a654fc0cd47791501945fc377c6e86405904ac9`

It intentionally demonstrates only a narrow evidence-backed surface: an agent
completion message is not automatically the authoritative result; a documented
incident replay includes a refusal and separately evaluated correction; and a
separate historical live run records persisted effect evidence.

It does not silently inherit the private research packet.

## 7. Document hierarchy

### Current

1. **This file** — current canonical thesis/program/status entry point.
2. [`research/ADMISSIBLE_POST_LITERATURE_THESIS_V0.6.md`](research/ADMISSIBLE_POST_LITERATURE_THESIS_V0.6.md)
   — byte-identical operative V0.6 object later adopted by the owner.
3. [`research/ADMISSIBLE_POST_NQI05_SYNTHESIS.md`](research/ADMISSIBLE_POST_NQI05_SYNTHESIS.md)
   — accepted NQI implications and effect-boundary/M2 allocation.
4. [`research/ADMISSIBLE_RESEARCH_CLOSURE.md`](research/ADMISSIBLE_RESEARCH_CLOSURE.md)
   — final SV-01 and dedicated-research status.
5. [`public/ADMISSIBLE_PUBLIC_CANONICAL_DEMO_V0.1.md`](public/ADMISSIBLE_PUBLIC_CANONICAL_DEMO_V0.1.md)
   — bounded public evidence-backed demo.

### Historical / superseded as current thesis

The following remain in place for provenance and must not be read as the
current research thesis or benchmark plan:

- [`Admissible_THESIS.md`](Admissible_THESIS.md) — pre-literature private V0.2
  thesis draft; superseded as the current research thesis by the owner-adopted
  post-literature V0.6 disposition and later program outcomes.
- [`Admissible_BENCHMARK_SPEC.md`](Admissible_BENCHMARK_SPEC.md) — pre-literature
  benchmark draft with baseline assumptions that are no longer the current
  scientific comparison standard.
- [`thesis.md`](thesis.md) — historical Agent OS thesis, not the current
  Admissible thesis.

Their bytes are intentionally preserved; their historical status is established
by this current entry point and the repository history rather than by rewriting
them retroactively.

## 8. Hard non-claims

Current documentation does **not** claim:

- research novelty or distinctiveness;
- that failure to establish novelty proves that no novelty exists;
- benchmark superiority or positive differential value;
- that SV-01 established treatment distinctness;
- that SV-01 established clean treatment non-distinctness;
- that the SV-01 benchmark was executed;
- universal safety;
- production readiness;
- M2 necessity as a security or research primitive;
- Admissible ownership of physical commit/settlement semantics;
- independent M2 acceptance or installed/clean-host qualification;
- that the documented public replay is a matched live refusal-to-authorization
  pair.
