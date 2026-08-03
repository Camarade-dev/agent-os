# Admissible Paired Runner — Milestone 0 Foundation Freeze

Status: `FOUNDATION_FREEZE_VERIFIED` at the documentation boundary, with the
explicit limitations recorded below. This file freezes provenance and build
inputs only. It does not implement, build, install, launch, or authorize a
paired runner.

## Scope and authority

This freeze executes only Milestone 0 of
`implementation/governing-inputs/PAIRED_LONG_RUNNING_RUNNER_GOVERNING_IMPLEMENTATION_PLAN_V0.1.md`.
The plan and the readiness audit were read in full before this change. Their
committed digests are recorded in `SOURCE_OF_TRUTH.json`.

The following actions were outside the freeze and were not performed:

- no functional `admissible.paired_runner` package was created;
- no benchmark task or benchmark preparation was created;
- no Codex, Cursor, provider, or other model was launched by this work;
- no provider or external service was contacted;
- no owner authorization was created, consumed, refreshed, replaced, or tested;
- no mint was created and no witness was refreshed;
- no V14, V15, V16, V17, or V18 action was executed or rerun;
- no V14–V18 source, evidence, runtime, installation, or terminal artifact was
  modified;
- no production `/opt`, `/etc`, `/var/lib`, or `/run` authority root was
  written.

The current shell is hosted by an existing Codex execution environment. A
read-only process inventory therefore shows pre-existing Codex orchestration
processes, but no target provider binary, Cursor binary, installed canary
launcher, owner provisioner, witness collector, or paired-runner process was
started by this freeze.

## Selected canonical repository and starting commit

| Field | Frozen value |
|---|---|
| Canonical repository | `/home/stris/work/agent-os-capsule-integration` |
| Branch | `paired-runner/m0-foundation-freeze` |
| Exact starting commit | `ab3e712121d29c318c59656e34d481b98100e896` |
| Starting tree object | `d6515157728f3680f95e7fb25e7a5ba8e09442c6` |
| Starting commit message | `docs: add paired runner governing inputs` |
| Starting worktree state | clean |
| Governing-input directory | `/home/stris/work/agent-os-capsule-integration/implementation/governing-inputs` |
| Future package namespace | `admissible.paired_runner` |
| Future package path | `/home/stris/work/agent-os-capsule-integration/admissible/paired_runner` |

The five files produced by this freeze are documentation and manifests. The
future package path is intentionally absent and is not a source root.

## Host assumptions and observed host

The repository README claims the modern judge-facing product for Windows with
Python 3.12, Git 2.45, Node.js 22, and npm 10. It explicitly does not claim
Linux or macOS as validated product platforms. The strong installed canary
path is a separate Linux-oriented Codex app-server path using bubblewrap.

The audit host observed during this freeze is:

| Input | Observed identity | Interpretation |
|---|---|---|
| OS | Linux 6.18.33.2-microsoft-standard-WSL2, `linux-x86_64` | Not a claimed modern-product host |
| Python | CPython 3.12.3, `/usr/bin/python3` -> `/usr/bin/python3.12` | `sha256=1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118` |
| Git | 2.43.0 | Differs from README validation claim |
| Node.js | unavailable on `PATH` | Product/UI qualification cannot be claimed here |
| npm | 10.8.2 command present, Node unavailable | Not a usable Node toolchain by itself |
| bubblewrap | 0.9.0 | Relevant to the installed canary reference only |
| dependency lock | none found | Reproducibility gap |
| wheel metadata | unavailable to the system interpreter | Offline packaging input is incomplete |

No future paired-runner host is selected by Milestone 0. Milestone 1 must make
one explicit choice and must not combine the Windows Cursor product assumptions
with the Linux Codex canary assumptions. A clean-host install and exact
entry-point qualification remain required later; the current host does not
physically establish them.

## Governing inputs

The committed manifest and recomputation at the start of the freeze were:

| Path | SHA-256 |
|---|---|
| `implementation/governing-inputs/PAIRED_LONG_RUNNING_RUNNER_GOVERNING_IMPLEMENTATION_PLAN_V0.1.md` | `0a4316efa770550e50b9218e15782e95a1f96c7440a1a9062a3bd80f6cbfbe24` |
| `implementation/governing-inputs/READINESS_AUDIT_GPT56SOL_XHIGH.md` | `4802411063a144b6983d64cc2e7ffab0a64665f4fcd9a88cf2c04c3d8809c4ab` |
| `implementation/governing-inputs/GOVERNING_INPUTS.sha256` | `7622b0470a39b41df308a168bec8e5adbfdf3327d866f2684b9a8a847060611c` |

## Relevant repositories, commits, and worktrees

The canonical repository is the only repository selected for future source
changes. The other roots are references or historical audit worktrees.

| Repository/worktree | Commit | Branch state | Status at inspection | Role |
|---|---:|---|---|---|
| `/home/stris/work/agent-os-capsule-integration` | `ab3e712121d29c318c59656e34d481b98100e896` | `paired-runner/m0-foundation-freeze` | CLEAN | selected canonical source |
| `/home/stris/work/agent-os-canary-launch-entrypoint-independent-audit-v1` | `9bf95b03318f6f469141aaa506238d05308a07f9` | detached | CLEAN | historical canary audit |
| `/home/stris/work/agent-os-canary-launch-entrypoint-repair-independent-audit-v1` | `827d42deea6f05ae864e58c7afd9004b1d7bf65f` | detached | CLEAN | historical canary audit |
| `/home/stris/work/agent-os-canary-launch-entrypoint-repair-v2-independent-audit-v1` | `638bddc0284e08d0a716357d8a1dab1eb8c35641` | detached | CLEAN | historical canary audit |
| `/home/stris/work/agent-os-canary-launch-entrypoint-v1` | `638bddc0284e08d0a716357d8a1dab1eb8c35641` | `canary/chatgpt-launch-entrypoint-repair-v2` | CLEAN | historical canary source |
| `/home/stris/work/agent-os-canary-preflight-v2` | `968b8af8540a92d27166219129f795e535164cec` | detached | CLEAN | historical owner/canary source |
| `/home/stris/work/agent-os-canary-preflight-v3` | `fdb009a67cabef6d4d2261638457446452a4e494` | detached | CLEAN | strong installed canary source reference |
| `/home/stris/work/agent-os-capsule-audit` | `22b0b294388bee07abbe4104e0a74cdf3861898e` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-capsule-auth-boundary-audit` | `fc7ed13523cebcc5e9de27f63f7252dcb0a24d7a` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-capsule-backend-audit` | `bea209d0c3f4255f78fc6273fcc60288651bd2b7` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-capsule-integration-final-audit` | `e0d1df949ba49af8eaee0741b2ac830a19a4d9b0` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-capsule-model-binding-audit` | `11b1bcefdac50c2df279db295f1a556ff637cf63` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-capsule-model-trust-audit` | `652d8c3c229308f3500e4b10feed5278868eaf15` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-capsule-owner-root-audit` | `86e72231a9d8f128b5ae9d5e1390e8dcaa5ee65f` | detached | CLEAN | historical audit |
| `/home/stris/work/agent-os-owner-final-code-audit` | `0b1c41a5cdb9e94950cdffc633c79f05cedccf14` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-final-ops-audit` | `0b1c41a5cdb9e94950cdffc633c79f05cedccf14` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-install-repair-code-audit` | `29ac091f373212e26fa73513d89a85427c8e33fb` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-install-repair-ops-audit` | `29ac091f373212e26fa73513d89a85427c8e33fb` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-root-code-audit` | `f6080288f9c519da7ad13f24412444e28b81222f` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-root-narrow-final-audit` | `2bf738cd6d254970fcc0b57b75310dd7d7a5e866` | detached | CLEAN | modern source audit |
| `/home/stris/work/agent-os-owner-root-narrow-independent-audit-v2` | `968b8af8540a92d27166219129f795e535164cec` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-root-ops-audit` | `968b8af8540a92d27166219129f795e535164cec` | detached | CLEAN | historical owner audit |
| `/home/stris/work/agent-os-owner-root-ops-final-audit` | `ffd9888f156558b8ffb4fdb646e15a8848b5ffa8` | detached | CLEAN | historical owner audit |

The nested reference repository
`/home/stris/work/admissible-capsule/spike-v1/finalizer-v1/reference/agent-os`
was separately checked clean at detached commit
`2f57ab503eb90d6e15601f26bd3098ab0aff4008`. It is historical reference
material, not a worktree of the selected canonical checkout.

## Authoritative source roots

1. **Selected future source root:** the clean canonical checkout at the
   starting commit above. Its product source is under
   `admissible/product_*` and `admissible/delegated_gate`; its strong
   canary-adjacent source is under `admissible/capsule`.
2. **Strong canary reference source:** the clean detached
   `/home/stris/work/agent-os-canary-preflight-v3` at
   `fdb009a67cabef6d4d2261638457446452a4e494`. It is a provenance source for
   extraction/composition review only. It is not the selected source commit and
   it is not imported implicitly.
3. **Historical reference source:** the nested `spike-v1` repository and the
   historical `admissible/runner`, `high_autonomy`, `long_run`, and
   `historical_pairing` modules. They are not future runtime inputs.

The current product source and the strong canary source are not the same
artifact: the target checkout's `host_codex_backend.py`,
`boundary_launcher.py`, and `capsule_broker.py` digests differ from the
installed v6 archive members, while the shared `native_executor.py`,
`managed_process.py`, and owner `records.py`/`state.py` files match the canary
worktree. This difference is recorded, not silently reconciled.

## Installed artifact roots and executable identities

All entries in this section were inspected read-only. They are historical or
production-authority objects; none is an input to a future mutable run.

| Object | SHA-256 | Role and boundary |
|---|---|---|
| `/opt/admissible-capsule-canary-launcher-v6/admissible-capsule-canary-launcher.pyz` | `f866366f65e7566354e65eaa91fcabb0f3ea69267588bd707efe1c7b50325b71` | installed strong canary launcher; immutable reference |
| `/opt/admissible-capsule-canary-launcher-v1/admissible-capsule-canary-launcher.pyz` | `87a86ba0f0d18575bdb799efcd334ae789396b87ccde9a3b4d82efdd02c357f0` | obsolete installed launcher; excluded |
| `/opt/admissible-codex-canary-v1/bin/codex` | `a2a05dafaa1acb002a45eaec0a462de5b13694fcfcd7bc43305f14781ce7be14` | pinned historical canary executable; not launched |
| `/opt/admissible-capsule-canary-exec-helper-v1/fd-sanitized-launch.py` | `5c6839b7f431cb351526411a3412e0ccdc5201e84eb3b6dc6c75402c22cc186b` | historical helper; immutable reference |
| `/opt/admissible-owner-authority-v1/broker.pyz` | `3ea5f31e37393d046600f9c6c51c5e7d5647a6cbedd9a93f61aaf87a94380493` | production broker; inspection only, never a test root |
| `/etc/admissible-owner-authority-v1/installation-v1.json` | `32b3c14176373ea9a002c6927fba3a9a28cff77f91d1ea434ce93774b8790c87` | production installation identity |
| `/etc/admissible-owner-authority-v1/owner-authority-signing-key.v1.pub.pem` | `1e6d4d40829284c8acab792ebddc01c7856318a75e5fe63b3adc5d4863855838` | production public verification key |
| `/run/admissible-owner-authority-v1/pending-authorization-witness.v1.json` | `721798752f6c5efacbcfda74dfe91b549b1ff0d954825c4b84aa3b02f01478ba` | current production witness; read-only evidence only |

The v6 archive's selected members match the corresponding files in the
`fdb009a` canary worktree for `canary_launch.py`,
`host_codex_backend.py`, `boundary_launcher.py`, `capsule_broker.py`,
`owner_authority/records.py`, and `owner_authority/state.py`. `unzip` emits a
warning about 23 extra bytes in the v6 archive; member-byte comparison still
succeeded. This is an installed artifact qualification limitation, not
permission to repair the artifact.

## Evidence roots and immutable historical roots

| Root/object | Identity | Classification |
|---|---|---|
| `/home/stris/work/admissible-capsule/canary-preflight-v14` | 189 files, 32 directories at inspection; final-generation `GENERATION.json` SHA-256 `854af52fc45531ee48d4dc0b086ac867456f4ba7d8d6f306746194cc3ceb9d31` | immutable V14 preparation/evidence |
| `/home/stris/work/admissible-capsule/canary-preflight-v14/rehearsal-evidence/v14-authorized-world/envelope/final-generation` | `GENERATION.json`, final `hashes.sha256`, sealed publication ledger | fixed one-turn canary preparation; not future benchmark |
| `/home/stris/work/admissible-capsule/canary-preflight-v14/rehearsal-evidence/v14-authorized-world/envelope/BIND_STATE.json` | SHA-256 `674251343d455ddf463d3c1d61f150cc172baa135f04a0a92cc30f5b950c871e` | immutable witness/bind evidence |
| `/home/stris/work/admissible-capsule/canary-preflight-v15` | 74-file planning manifest plus preserved recovery material | consumed one-shot recovery evidence |
| `/home/stris/work/admissible-capsule/canary-preflight-v16` | bundle manifest SHA-256 `5b429ca9d255d06a4236d9083e604317fdbb38e053df83f5e78e18361c875b35` | consumed recovery evidence |
| `/home/stris/work/admissible-capsule/canary-preflight-v17` | bundle manifest SHA-256 `f5711fa01594a95934fe92490bd936b30393e83373e3b4ec869d9b25e35a5cd9` | consumed recovery evidence |
| `/home/stris/work/admissible-capsule/canary-preflight-v18` | bundle manifest SHA-256 `6f4f05d044ee5f7b38a125a9e99435d85ce5b73141d58ff22247be2ae53d82ef` | recovery evidence; terminal pointer below |
| `/home/stris/work/admissible-capsule/canary-preflight-v18/recovery-evidence/V18_RECOVERY_TERMINAL_POINTER.json` | SHA-256 `ae17566b2f8161434ec913fedb883a4c2b9c4bb660881ceb4455d05c1d0b7353` | `V18_RECOVERY_SUCCESS`, stops before execution |
| `/home/stris/work/admissible-capsule/runs` | existing historical evidence root; no future run root | historical only |
| `/home/stris/work/admissible-capsule/spike-v1` | existing historical/reference root | historical only |
| `benchmark/reports/admissible_frontier_model_comparison_initial.md` | preserved report; Condition A is pending/not created | historical comparison evidence |
| `benchmark/live_rehearsal_workspace_027b/session_export_027b.json` | preserved product rehearsal export | historical comparison evidence |

The V18 pointer identifies the V14 final generation and the V14 bind state,
records `no_new_codex_execution=true` and `no_new_mint=true`, and classifies
the result as `V18_RECOVERY_SUCCESS`. That is evidence of bounded recovery,
not evidence of a paired benchmark.

## Reusable-component provenance table

Classification is exactly one of `APPROVED_FOR_EXTRACTION`,
`APPROVED_FOR_COMPOSITION`, `REFERENCE_ONLY`, `EXCLUDED`, or `UNRESOLVED`.
“Approved” means approved for a future explicit extraction/composition review;
it is not permission to copy, build, install, or run anything in Milestone 0.

| Component | Physical provenance | Classification | Freeze boundary |
|---|---|---|---|
| Codex app-server transport | `fdb009a` `admissible/capsule/codex_protocol.py`, `host_codex_backend.py`; installed v6 member bytes | `APPROVED_FOR_EXTRACTION` | Re-extract with a new provenance record; same transport must serve A and B |
| Host backend | `fdb009a` `admissible/capsule/host_codex_backend.py`; installed member SHA-256 `a8ae5d5c…` | `APPROVED_FOR_EXTRACTION` | Candidate source only; current selected checkout has a different digest |
| Dynamic tool grammar | `fdb009a` `dynamic_tools_grammar()` with `list_files`, `read_file`, `write_file`, `run_command` | `APPROVED_FOR_EXTRACTION` | Preserve the four-tool boundary unless a later ADR changes it |
| Boundary launcher | `fdb009a` `admissible/capsule/boundary_launcher.py` and installed member | `APPROVED_FOR_COMPOSITION` | Compose with a future generic runner only after host and runtime qualification |
| Confinement | descriptor-bound bubblewrap/private mount, PID, and network namespace path in the canary launcher | `APPROVED_FOR_COMPOSITION` | Production confinement is not a test root and is not modified |
| Canonicalization | canary `admissible/capsule/common.py` canonical bytes/fingerprint plus V14 canonical publication records | `APPROVED_FOR_EXTRACTION` | Reuse only with explicit schema/version ownership |
| Publication durability | canary effect ledger and V14 atomic publication/fsync ledger | `APPROVED_FOR_EXTRACTION` | Must be retested for the generic multi-session state model |
| Owner broker | installed `/opt/admissible-owner-authority-v1/broker.pyz`, canary broker source, root-generated record protocol | `APPROVED_FOR_COMPOSITION` | Compose only behind a disposable authority root in later milestones; never use production root |
| Authorization records | `fdb009a` `owner_authority/records.py`; signed payload/receipt identities | `APPROVED_FOR_EXTRACTION` | Generic envelope fields and expiry remain open work |
| Authority state machine | `fdb009a` `owner_authority/state.py`; durable `O_EXCL` consumption and forward-only state | `APPROVED_FOR_EXTRACTION` | Current pending state has no effective expiry/revocation; repair requires a later ADR |
| Signed consumption receipts | canary owner authority signing/receipt path and V14 physical consumer matrix | `APPROVED_FOR_EXTRACTION` | Receipt schema must be generalized without weakening no-replay semantics |
| Witness binding | V14 `BIND_STATE.json`, V18 witness-bound terminal pointer, current production witness | `REFERENCE_ONLY` | Never use the current witness as a future runner input |
| Physical consumer verification | V14 physical consumer matrix and canary pre-effect identity revalidation | `APPROVED_FOR_EXTRACTION` | Extract verification logic only after defining generic consumers |
| Terminal-state evidence | canary terminal classification/finalizer/read-model evidence | `APPROVED_FOR_EXTRACTION` | Must be reconciled with the future terminal manifest and independent evaluator |
| Cursor `--force --trust` product path | `admissible/delegated_gate/native_executor.py`, `native_canary.py`, product launcher | `EXCLUDED` | It is a separate modern product path, not Condition B |
| Operator-log Condition A materials | preserved comparison protocol/report and `frontier_comparison_metrics.py` observation-log branch | `EXCLUDED` | Not an execution-grade baseline runner |
| `baseline_runner.py` | `admissible/runner/baseline_runner.py`, SHA-256 `64a01f8f…` | `EXCLUDED` | It evaluates action-envelope decisions, not engineering execution |
| Historical multi-turn/high-autonomy modules | `long_run_*`, `high_autonomy_*`, `historical_pairing_*`, historical runner modules | `EXCLUDED` | No implicit import, revival, or version continuation |
| V14 final-generation | `/home/stris/work/admissible-capsule/canary-preflight-v14/rehearsal-evidence/v14-authorized-world/envelope/final-generation` | `EXCLUDED` | Fixed `native-codex-chatgpt-canary-010` one-turn preparation; not future benchmark |
| V14 `BIND_STATE.json` | immutable bind-state evidence at the path above | `REFERENCE_ONLY` | Evidence of provenance and authority-chain behavior only |
| V18 recovery evidence | V18 terminal pointer and bind report | `REFERENCE_ONLY` | Recovery stops before authorization/execution; do not repurpose |
| Obsolete installed launcher copies | `/opt/admissible-capsule-canary-launcher-v1/*.pyz` | `EXCLUDED` | Do not delete or use as a future source |
| Current production witness and owner-authority installation | `/etc`, `/var/lib`, `/run`, and installed production broker roots | `EXCLUDED` | Read-only inspection only; never mutable test input |

## Proposed future namespace and extraction policy

The proposed namespace is `admissible.paired_runner`, with the future package
path `admissible/paired_runner/`. The plan's candidate module names are
`canonical.py`, `schemas.py`, `specification.py`, `identities.py`,
`observation.py`, `effects.py`, `process_supervision.py`, `state.py`,
`store.py`, `checkpoint.py`, `transport.py`, `direct_mode.py`,
`governed_mode.py`, `policy.py`, `authority.py`, `evaluator.py`,
`comparison.py`, `archive.py`, and `cli.py`.

These names are planning identities only. No directory or module was created.
Any future extracted component must:

1. name its exact source worktree and commit;
2. record the source and installed digests;
3. identify the governing requirement and ADR;
4. record API/schema adaptations;
5. be tested on a disposable authority root;
6. be included in a new build manifest before installation.

No future build may import the legacy `admissible.runner`, `high_autonomy`,
`long_run`, or `historical_pairing` paths merely because they remain present.

## Migration and extraction risks

- The selected source commit is `ab3e712`; the strong installed canary source is
  `fdb009a`, and the canary transport files have different bytes. A future
  extraction must produce a new explicit commit rather than mixing worktrees.
- The modern product uses Cursor package-bin/native tools with `--force --trust`
  and has no OS sandbox; the strong canary uses Codex app-server dynamic tools
  and confinement. Combining them would invalidate A/B causality.
- The product imports optional historical-pairing modules and retains many
  historical modules. Import presence is not approval for future use.
- The current installed v6 zipapp has a 23-byte structural warning. Its member
  bytes match the fdb source, but clean-host artifact qualification is still
  open.
- The owner broker has strong one-shot consumption and signed receipts, but the
  audit found no effective pending expiry/revocation. No production repair is
  authorized here.
- The product has no dependency lock, is documented for Windows, and is not
  installed on this Linux host. Build reproducibility and entry-point parity
  remain open.
- The current one-shot process path retains an unbounded stream queue despite a
  bounded text cap. Long-output repair belongs to a later milestone.
- The canary's logical independent verification copies re-read one physical
  root. The future evaluator must not inherit that overclaim.

## Read-only and mutating boundaries

| Boundary | Permitted in this freeze | Prohibited in this freeze |
|---|---|---|
| Repository | `git rev-parse`, `git status`, `git worktree list`, `git ls-tree`, source reads, digest comparisons | functional source edits, package creation, build/install |
| Installed artifacts | `stat`, `file`, `sha256sum`, `unzip -l`, `unzip -p` for comparison | execution, replacement, relabeling, deletion |
| Evidence roots | static reads and digest verification | V14–V18 scripts, action entry points, evidence writes |
| Production authority | static inspection of installation/public witness bytes | provisioner, broker consumption, witness collector, refresh, replacement, `/opt`/`/etc`/`/var/lib`/`/run` writes |
| External boundaries | none | provider, model, network, external service, `git fetch`, package download |
| Freeze outputs | five repository-local documentation/manifests and one Git commit | functional runtime packages or future benchmark |

## Why V14–V18 cannot authorize or identify the future benchmark

V14–V18 are historical identities with one-shot and terminal-state protections.
Their final generation binds a fixed `native-codex-chatgpt-canary-010` mission,
one model turn, one write effect, and a canary-specific owner payload. V18
recovery proves that the existing bind state and witness chain were recovered
without creating a new mint, authorization, or Codex execution; it therefore
stops before the boundary that would authorize a run.

Those artifacts do not contain a future benchmark task, paired A/B
specification, common evaluator, multi-session budget, or new initial snapshot.
Using them as future authority would violate ADR-011, AUTH-09, the plan's
explicit prohibition on V14 reuse, and the one-shot semantics they were built
to protect. They remain immutable evidence and cannot be reinterpreted as
benchmark preparation.

## Milestone 1 and later decisions left open

- select and qualify one future experiment host and offline toolchain;
- define the exact source extraction commit and package import closure;
- specify canonical proposal, observation, effect, state, checkpoint, evaluator,
  and comparative schemas;
- define one pinned model executable and continuation semantics;
- define identical A/B non-governance inputs and the allowlisted governance
  difference;
- define disposable authority-root, expiry, cancellation, revocation, and
  replay behavior;
- repair bounded output handling and prove long-running restart behavior;
- define dependency, network, filesystem, Git, process, time, token, and human
  intervention budgets;
- define a generic independent evaluator without selecting or creating a future
  benchmark task;
- qualify the exact installed entry points on a clean host;
- obtain an independent closure audit before any benchmark freeze or real
  authority ceremony.

## Milestone 0 disposition

The five Milestone 0 requirements are frozen as follows:

| Requirement | Disposition |
|---|---|
| ARCH-01 | `DESIGNED`: canonical source commit and build-input manifest are frozen; no future artifact is yet built |
| ARCH-03 | `VERIFIED_UNIT`: historical and excluded paths are explicitly named in the manifests and provenance table |
| ARCH-06 | `VERIFIED_UNIT`: selected source, canary reference, and installed member digests are recorded and recomputed where accessible |
| OPS-07 | `DESIGNED_WITH_EXPLICIT_LIMITATION`: source entry points are identified, but clean-host installed parity is deferred because the product is not installed on this host and the future package does not exist |
| AUTH-09 | `VERIFIED_UNIT`: every V14–V18 identity is explicitly excluded from new-run authority |

This is the end of Milestone 0. No Milestone 1 work is started by this commit.
