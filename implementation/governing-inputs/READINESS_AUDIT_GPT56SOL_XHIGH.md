# 1. Executive verdict

**`NOT READY FOR EXPERIMENT PLANNING`**

V18 genuinely reached `V18_RECOVERY_SUCCESS`, and the recovered generation is intact, production-authoritative, witness-bound, and explicitly stopped before authorization or execution. That object is a fixed one-turn `CANARY.txt` preparation for `native-codex-chatgpt-canary-010`, not a reusable preparation for a future benchmark. No single, installed, connected path currently supports a generic multi-hour governed engineering task. The current judge-facing product is one-shot, limited to 3,600 seconds, uses a different Cursor execution architecture, is not installed here, and cannot import on this Linux host. The available Condition A material is an operator-log protocol rather than an instrumented direct-execution runner, while preserved comparison evidence says Condition A remained pending. Generic independent acceptance, cross-condition equivalence, resource accounting, resumability, and production-path validation are missing. The privileged one-shot authority chain and canary evidence architecture are strong reusable foundations, but several architectural choices must be resolved before an experiment plan can be frozen. This verdict does not authorize implementation, preparation, owner finalization, or execution.

# 2. Source-of-truth map

## Repositories and source

| Role | Physical source of truth | State |
|---|---|---|
| Main modern product repository | `/home/stris/work/agent-os-capsule-integration` | Clean, detached `2bf738cd6d254970fcc0b57b75310dd7d7a5e866` |
| Installed canary/owner source | `/home/stris/work/agent-os-canary-preflight-v3` | Clean, detached `fdb009a67cabef6d4d2261638457446452a4e494` |
| Current judge-facing product packages | [README.md](/home/stris/work/agent-os-capsule-integration/README.md:17): `product_launcher`, `product_service`, `product_ui`, `product_read_model`, `delegated_gate` | Source-only; not installed |
| Privileged capsule path | [canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:1), `admissible/capsule/*`, `owner_authority/*` | Installed for the fixed canary |
| Historical multi-turn/high-autonomy code | Same Git repository, outside the judge-facing package set | Historical/disconnected; README expressly excludes it from the product path |
| Nested reference repository | `/home/stris/work/admissible-capsule/spike-v1/finalizer-v1/reference/agent-os` | Clean, detached `2f57ab503eb90d6e15601f26bd3098ab0aff4008`, historical reference |
| Audit/evidence root | `/home/stris/work/admissible-capsule` | Not a Git repository; its `.git` is only an empty read-only directory |

All 23 registered worktrees were clean. The modern `2bf738c` commit is an ancestor of `fdb009a`; the judge-facing product directories and `managed_process.py` do not differ between them. No current branch names `fdb009a`, while an older branch points at `638bddc`, leaving release selection operationally ambiguous.

## Installed runtime artifacts

| Artifact | Identity and role |
|---|---|
| Current canary launcher | `/opt/admissible-capsule-canary-launcher-v6/admissible-capsule-canary-launcher.pyz`, SHA-256 `f866366f65e7566354e65eaa91fcabb0f3ea69267588bd707efe1c7b50325b71` |
| Obsolete launcher copy | `/opt/admissible-capsule-canary-launcher-v1/admissible-capsule-canary-launcher.pyz`, SHA-256 `87a86ba0…`; not named by the recovered preparation |
| Pinned model executable | `/opt/admissible-codex-canary-v1/bin/codex`, Codex `0.145.0`, SHA-256 `a2a05dafaa1acb002a45eaec0a462de5b13694fcfcd7bc43305f14781ce7be14` |
| FD-sanitized helper | `/opt/admissible-capsule-canary-exec-helper-v1/fd-sanitized-launch.py`, SHA-256 `5c6839b7…` |
| Owner broker | `/opt/admissible-owner-authority-v1/broker.pyz`, SHA-256 `3ea5f31e37393d046600f9c6c51c5e7d5647a6cbedd9a93f61aaf87a94380493` |
| Owner installation record | `/etc/admissible-owner-authority-v1/installation-v1.json`; installation ID `6d730d…`, authorized UID/GID `999/989`, Ed25519 key fingerprint `ca8808…` |
| Owner durable/runtime roots | `/var/lib/admissible-owner-authority-v1`, `/run/admissible-owner-authority-v1` |
| Current witness | `/run/admissible-owner-authority-v1/pending-authorization-witness.v1.json`; current boot ID, collector-v2 identity, no recorded conflicts |
| Judge-facing `admissible` CLI | Not present on `PATH`; package import fails in the system Python |

The installed v6 copy of `canary_launch.py` exactly matches the `fdb009a` source file at SHA-256 `850bee881c4e9dd396d97ba7f29f560a79fdbb0698e0e1f93ff2efc835ea5839`.

## Evidence roots

- V14: `/home/stris/work/admissible-capsule/canary-preflight-v14`; recovered final generation under [final-generation](/home/stris/work/admissible-capsule/canary-preflight-v14/rehearsal-evidence/v14-authorized-world/envelope/final-generation/GENERATION.json).
- V15–V17: preserved recovery attempts; consumed one-shots, never eligible for rerun.
- V18: `/home/stris/work/admissible-capsule/canary-preflight-v18`; terminal pointer [V18_RECOVERY_TERMINAL_POINTER.json](/home/stris/work/admissible-capsule/canary-preflight-v18/recovery-evidence/V18_RECOVERY_TERMINAL_POINTER.json).
- Durable recovered bind: [BIND_STATE.json](/home/stris/work/admissible-capsule/canary-preflight-v14/rehearsal-evidence/v14-authorized-world/envelope/BIND_STATE.json).
- Historical run evidence: `/home/stris/work/admissible-capsule/runs` and `spike-v1`; neither is the future experiment root.
- Preserved governed comparison: [initial report](/home/stris/work/agent-os-capsule-integration/benchmark/reports/admissible_frontier_model_comparison_initial.md:1) plus `benchmark/live_rehearsal_workspace_027b/session_export_027b.json`.
- No physical Condition A run directory or observation log was found.

All V14 final-generation hashes verified. Preserved results record 78 passing V14 offline cases and 220 passing V18 static/fixture checks, with zero model, provider, mint, collector, broker, or bind executions during those test suites.

# 3. Current end-to-end architecture

## Lifecycle map

| Stage | Current component and flow | Authority, mutation, evidence, failure/retry | Status |
|---|---|---|---|
| 1. Task definition | Product authoring emits mission profile v2; canary uses fixed 35-byte mission | Product allows a fixed golden profile or weak `OBSERVED_ONLY` generic profile; canary cannot vary | **Implemented but unproven** |
| 2. Initial snapshot | Product records source HEAD and creates/observes a workspace; canary binds exact repository/destination identities | Product does not require clean source, dependency, environment, or toolchain fingerprint | **Implemented but unproven** |
| 3. Model invocation | Product would launch Cursor package-bin/wrapper; installed canary launches pinned Codex app-server | Product path is uninstalled; canary is one model turn only | **Fixture-only** for the installed path |
| 4. Tool exposure | Product Cursor receives its normal native capabilities; canary exposes four dynamic tools | Product has no OS sandbox or per-tool mediation; canary disables native/MCP/web/skills and uses a read-only Codex thread | **Implemented and connected** only for canary |
| 5. Proposal/action generation | Product child edits directly; canary turns dynamic-tool requests into bounded capsule effects | Product proposals are not separately admitted before mutation | **Missing** for generic per-action governance |
| 6. Preparation | Product retains preparation in memory; V14 final generation is durable and sealed | Product TTL is ineffective; V14 object is immutable but canary-specific | **Implemented and connected** only for canary |
| 7. Evidence capture | Product writes request/process/Git/checkpoint/terminal records; canary writes effect journal, receipts, intake, finalization | Product package-bin lacks authoritative per-native-tool receipts and resource metrics | **Implemented but unproven** |
| 8. Policy evaluation | Product performs contract checks and post-run Git/checkpoint evaluation; canary has 18 pre-effect gates | Product package-bin relies partly on prompt restrictions; canary refuses before effects | **Implemented and connected** only in their separate scopes |
| 9. Authority decision | Product uses in-process phrase digest; canary uses privileged broker receipt | Strong authority is not connected to the product | **Implemented but unproven** |
| 10. Owner review | Product UI renders contract; canary renders exact owner payload summary | Canary summary binds source, model, tools, destination, runtime dependencies and budgets | **Implemented and connected** for canary |
| 11. Owner authorization | Privileged provisioner creates one pending record; product accepts caller-provided digest | No future-benchmark payload exists; provisioning CLI is not installed here | **Implemented but unproven** |
| 12. Execution | Product starts one native Cursor process; canary starts one confined Codex turn | Both are one-shot; neither is a connected multi-session benchmark executor | **Missing** for the intended experiment |
| 13. Receipt generation | Canary broker signs exact consumption receipt; product records process/evidence artifacts | Modern product lacks broker-signed launch authority | **Implemented and connected** only for canary |
| 14. State transition | Broker state is durable and forward-only; product control state is in memory | Product can rediscover completed evidence but not resume active control state | **Implemented but unproven** |
| 15. Acceptance | Canary checks exact `CANARY.txt`; golden product profile runs a fixed verifier; default profile is observational | No generic benchmark evaluator or shared A/B acceptance contract exists | **Missing** |
| 16. Archive/terminal closure | Canary produces terminal result and forward-only owner state; product has run evidence/read-model reconstruction | No comparative terminal manifest reconciles A and B | **Implemented but unproven** |

## Actual process boundaries

The installed canary entry point accepts only `--launch-plan` and `--owner-payload`; all other authority is derived, with no widening flags ([canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:9)). It binds `gpt-5.3-codex`, effort `low`, one model turn, one write effect, zero retries, no arbitrary command or network authority ([canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:93)). After all pre-effect gates, it consumes owner authority exactly once ([canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:3508)).

Codex is physically started as `app-server --stdio` ([boundary_launcher.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/boundary_launcher.py:80)) inside bubblewrap-managed private mount, PID, and network namespaces. The thread is ephemeral, approval is `never`, the Codex sandbox is read-only, fallback is disabled, and apps, skills, MCP, web, native shell, and native file capabilities are omitted ([host_codex_backend.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/host_codex_backend.py:1087)). The only grammar is `list_files`, `read_file`, `write_file`, and `run_command`, with relative paths and a ten-second command maximum ([host_codex_backend.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/host_codex_backend.py:983)). App-server/session records are durable for reconstruction, but the launch is still one thread and one turn, without continuation across invocations.

The modern product would follow:

```text
admissible CLI/UI
  → ProductControlPlane
  → ProductionChildApplication
  → run_native_mission_application
  → NativeDelegatedExecutor
  → Node/Cursor package-bin or wrapper-chain
  → cursor --print --output-format stream-json --force --trust --model …
```

The exact package-bin command is built in [native_executor.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/native_executor.py:1863). Its permission policy is expressly not a sandbox ([native_executor.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/native_executor.py:252)); authority is enforced through contract construction, prompt restrictions, process supervision, and post-run evidence. The child runs once, in a copied work workspace, with an environment allowlist, a maximum 3,600-second timeout, process-tree cleanup, bounded retained stdout/stderr, and no automatic retry or session resume.

## Ownership finalization

The intended privileged surface renders:

```sh
exec 3< <(systemd-ask-password --echo=no 'Owner authorization phrase:')
sudo python3 -m admissible.capsule.owner_authority.provisioner provision \
  --owner-payload <payload.json> \
  --phrase-fd 3
exec 3<&-
```

Source: [provisioner.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/provisioner.py:357).

The owner must also retype the exact payload fingerprint before provisioning ([provisioner.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/provisioner.py:606)). The digest binds a root-generated 32-byte record ID, construction identifier, phrase, canonical payload, and record ID ([records.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/records.py:137)). The record is stored beneath `/var/lib/admissible-owner-authority-v1/authorizations/<record-id>/pending.json`, mode `0400`, using `O_EXCL` and file/directory `fsync` ([state.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/state.py:109)).

A pending authorization has no expiry or revocation transition. If launch never happens, it remains `PROVISIONED_PENDING` and launchable indefinitely. Once phrase verification begins, consumption is durably committed before a receipt is signed, and no crash can restore launchability ([state.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/state.py:1)).

The recovered owner payload binds the canary repository/implementation commit, model and effort, executable, protocol, destination/tool authority, runtime dependencies, preparation, run identity, and one-launch/zero-retry budgets. It does **not** describe a future benchmark task and must not be reused.

## Acceptance and evidence

The canary distinguishes provider completion, process completion, effect success, intake, checkpoint, behavioral verification, Git finalization, and terminal acceptance. It requires exactly one `CANARY.txt` with exact bytes and one exact commit; the provider’s claim is not authoritative ([canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:4206)).

The modern product records:

- contract/profile, prompt and executable attestation fingerprints;
- attempt reservation and process-start evidence;
- exit, timeout, cleanup, output and Git observations;
- checkpoint and behavioral-verifier artifacts;
- terminal disposition;
- independent read-model reconstruction from durable evidence.

It does not currently record authoritative package-bin tool calls, CPU/RSS, token/cost usage, monotonic duration, or a common A/B observation schema.

# 4. Comparative-experiment matrix

Classification: **R** required experimental difference; **C** controllable and must be equalized; **M** measurable/reportable; **F** currently fatal.

| Variable | Condition A today | Condition B today | Classification |
|---|---|---|---|
| Task prompt | Manual protocol text | Profile-derived runtime prompt/canary mission | **F**: no byte-identical delivery path |
| Model/version | Unspecified “same class” | Cursor `auto` in product or fixed Codex in canary | **F** |
| Executable/digest | Not captured by baseline protocol | Cursor attestation or pinned Codex digest | **F** |
| Tool definitions | Agent’s normal tools | Native Cursor tools or four canary dynamic tools | Governance differences are **R**; current unrelated surfaces are **F** |
| Filesystem view | Fresh scratch by convention | Copied workspace or sealed capsule | Isolation is **R**; initial-content mismatch is **C** |
| Initial Git state | Manual observation | HEAD plus governed workspace records | **C**; dirty tree and refs need common capture |
| Dependencies/toolchain | Not pinned | Host prerequisites or capsule runtime subset | **C/M** |
| Environment variables | Not captured | Partial allowlist/authority evidence | **C/M** |
| Network | Agent may use normal network | Product lacks OS network sandbox; canary permits only controlled provider relay | Governance restriction is **R**, actual policy must be recorded |
| Time limit | Unspecified | Maximum 3,600 seconds | **C** |
| Token/cost budget | Unspecified/unmeasured | Unspecified/unmeasured | **F** for resource comparison |
| Retries | Normal workflow, undocumented | Zero in current profiles | Governance rule may be **R**, count must be **M** |
| Context continuation | Normal session possible | No current production continuation | **F** |
| Human assistance | Operator notes | Product UI plus authorization and prior manual corrections | Governance ceremony is **R**; corrections are **M** |
| Stop condition | Agent/operator judgment | Exact one-shot profile policy | **C**, beyond required authorization behavior |
| Acceptance tests | None shared | Canary-specific or fixed golden verifier | **F** |
| Post-run evaluation | Manual rubric | Governed read model/profile verifier | **F** |
| Evidence quality | Manual Condition A log | Structured Condition B records | **F** |
| Run order | Protocol executes B first | B already observed first historically | **M**; future order should be randomized or declared |
| Cache/session isolation | Convention only | Per-run workspace, but host caches may remain shared | **C** |

# 5. Requirement matrix

| ID | Requirement | Status | Evidence | Gap | Repair or validation |
|---|---|---|---|---|---|
| ARCH-01 | One authoritative source commit and installed build | Partial | Installed canary matches `fdb009a`; product root is `2bf738c` | Detached/duplicate roots; product uninstalled | Freeze one commit, build manifest, archive digest |
| ARCH-02 | Connected task-to-closure lifecycle | Missing | Stage map above | Canary and product paths diverge | Connect one physical path end-to-end |
| ARCH-03 | No historical module silently used as production | Partial | [README](/home/stris/work/agent-os-capsule-integration/README.md:27) | Old multi-turn substrate remains tempting but disconnected | Explicit runtime import/build manifest |
| EXEC-01 | Same model executable in A and B | Missing | V14 binds Codex; product uses Cursor | No common runner | Create paired launcher around one pinned executable |
| EXEC-02 | Governed effects pass through an authority boundary | Partial | Canary dynamic tools do; product package-bin does not | Strong path is canary-only | Generalize and connect the dynamic-tool/effect boundary |
| EXEC-03 | Multi-hour, supervised, cancellable execution | Missing | One-shot budgets and 3,600-second ceiling | No continuation/resume | Durable multi-invocation state and budgets |
| AUTH-01 | Model cannot self-authorize | Satisfied in canary | Privileged root-generated record and broker | Not true of modern product’s in-process digest boundary | Connect privileged broker |
| AUTH-02 | Authorization binds task/model/tools/source/run/budgets | Satisfied in canary | [OWNER_SUMMARY.txt](/home/stris/work/admissible-capsule/canary-preflight-v14/rehearsal-evidence/v14-authorized-world/envelope/final-generation/OWNER_SUMMARY.txt) | Object is fixed canary | Define a future benchmark payload schema |
| AUTH-03 | Expiry, cancellation and replay policy | Failed | Product TTL code; broker pending state | TTL ineffective; broker record never expires | Add expiry/revocation semantics and tests |
| EVID-01 | Common immutable run identity and initial fingerprint | Partial | Governed path has IDs/fingerprints | Baseline and full initial environment absent | Common observation envelope |
| EVID-02 | Authoritative tool/effect receipts | Partial | Canary effect journal | Package-bin and baseline lack equivalent observations | Instrument outside the authority intervention |
| EVID-03 | Timing/resource/retry/human metrics | Missing | Wall timestamps exist | No CPU/RSS/token/cost/monotonic accounting | Add common resource ledger |
| EVID-04 | Chain of custody from authorization to acceptance | Partial | Strong canary chain | No cross-condition terminal manifest | Comparative archival manifest |
| ACCEPT-01 | Generic independent task evaluator | Missing | Canary checks only `CANARY.txt`; product default is `OBSERVED_ONLY` | No benchmark acceptance contract | Freeze evaluator and hidden/held-out checks |
| ACCEPT-02 | Detect false claims and out-of-scope changes | Partial | Read model and canary refusal tests | Generic omissions/out-of-scope oracle absent | Add scope manifest and negative acceptance tests |
| BASE-01 | Direct execution harness | Missing | Historical protocol uses operator log | No executable paired runner | Implement observational baseline wrapper |
| BASE-02 | Instrumentation without governance restrictions | Missing | [metrics helper](/home/stris/work/agent-os-capsule-integration/admissible/runner/frontier_comparison_metrics.py:134) leaves evidence fields `None` | Evidence asymmetry | Move shared observation below/around both runners |
| FAIR-01 | Byte-identical task and initial state | Missing | Convention only | No paired snapshot manifest | Create two immutable clones from one snapshot |
| FAIR-02 | Same model, executable, budgets and context rules | Missing | Current paths differ | Fatal confounding | Freeze protocol fields and preflight equality gate |
| FAIR-03 | Human aid and order effects controlled | Partial | Historical protocol notes operator burden | No randomized/counterbalanced procedure | Prespecify assistance and order |
| LONG-01 | Multiple turns/sessions with persistent state | Missing | Historical code only | Production paths are one-shot | Durable task/session checkpoint protocol |
| LONG-02 | Restart, crash and partial-progress recovery | Partial | Process cleanup and owner crash safety are strong | No active-run resume | Add restart/rollback/stale-evidence rules |
| LONG-03 | Bounded large-log handling | Failed | Unbounded `_StreamPump.queue` | Memory grows with every line | Bound or continuously drain queues; soak test |
| LONG-04 | Dependencies, tests and Git policy suitable for real work | Missing | Current profiles forbid installs and require one commit | Too narrow for many long tasks | Freeze offline dependencies and broaden scoped Git authority |
| OPS-01 | Read-only readiness/preflight | Partial | V18 has clear status/readiness; product has UI preflight | No unified future-run preflight | One non-mutating readiness command |
| OPS-02 | Mutating/provider/authority commands clearly distinct | Partial | V18 plan is explicit | Product/provisioner installation unclear | Render classified commands before execution |
| OPS-03 | One-shot rerun protection | Satisfied for V15–V18 and broker | Durable markers and terminal pointer | Must remain separate from future run | Preserve and explicitly exclude these identities |
| TEST-01 | Negative authorization/evidence/process tests | Strong | Owner, capsule, native executor and read-model suites | Mostly synthetic/provider-free | Retain as regression base |
| TEST-02 | Exact installed production-boundary integration | Missing | V18 physical bind, but no canary execution; product uninstalled | No full offline physical rehearsal | Disposable-root installed-path integration |
| TEST-03 | Fairness, soak, resume and comparative tests | Missing | No such suite | Long-run risks untested | Add common-harness, restart, output and parity matrices |

# 6. Findings

## Blocker

### AUD-B01 — No connected generic governed long-running path

- **Affected component:** Product launcher, delegated executor, installed canary.
- **Location:** [README.md](/home/stris/work/agent-os-capsule-integration/README.md:17), [canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:1), [mission_profile.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/mission_profile.py:69).
- **Observed:** The installed path is a fixed one-turn canary. The generic product is source-only, one-shot, and disconnected from historical multi-turn code.
- **Expected:** One installed entry point supporting a generic, scoped, multi-session engineering mission through terminal acceptance.
- **Why it matters:** There is no physical Condition B path whose executable, state, authority and recovery behavior can be put into an experiment plan.
- **Confidence:** **Proven**.
- **Validation:** After repair, exercise the exact installed path provider-free in a disposable root through preparation, synthetic authority, effects, restart and acceptance.
- **Bounded repair:** Select one source commit and connect/generalize the capsule execution path rather than reviving historical modules implicitly.

### AUD-B02 — No execution-grade Condition A harness

- **Affected component:** Baseline protocol and comparison metrics.
- **Location:** [comparison protocol](/home/stris/work/agent-os-capsule-integration/docs/admissible-frontier-model-comparison-protocol.md:60), [frontier comparison report](/home/stris/work/agent-os-capsule-integration/benchmark/reports/admissible_frontier_model_comparison_initial.md:28), [baseline_runner.py](/home/stris/work/agent-os-capsule-integration/admissible/runner/baseline_runner.py:1).
- **Observed:** Condition A is specified as a normal agent run with an operator-authored log. The executable baseline runner evaluates action-envelope decisions, not software-engineering execution.
- **Expected:** A direct runner using the same model executable, prompt, workspace and budgets while recording authoritative observations without imposing Admissible admission.
- **Why it matters:** Task, correctness, resource, behavior and unauthorized-action comparisons cannot be reconstructed fairly.
- **Confidence:** **Proven**.
- **Validation:** Run paired provider-free synthetic agents and prove equality of every non-governance input.
- **Bounded repair:** Build one shared observation harness with direct and governed launch modes.

### AUD-B03 — Current product mediation is materially different from the strong canary boundary

- **Affected component:** `NativeDelegatedExecutor` and capsule dynamic tools.
- **Location:** [native_executor.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/native_executor.py:185), [native_executor.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/native_executor.py:252), [host_codex_backend.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/host_codex_backend.py:983).
- **Observed:** Product Cursor runs with `--force --trust` and normal native tools; restrictions are prompt- and post-observation-based. The preventive, per-tool dynamic boundary exists only in the fixed canary.
- **Expected:** Condition B’s consequential actions pass through a connected authority/effect boundary; Condition A alone bypasses it.
- **Why it matters:** Current A/B differences would combine model, executable, tool grammar, confinement and governance, defeating causal interpretation.
- **Confidence:** **Proven**.
- **Validation:** Trace every mutation from model protocol record to effect receipt under the same model transport in both modes.
- **Bounded repair:** Reuse the capsule dynamic-tool authority for a generic mission, or formally define and validate an equivalent governed action transport.

### AUD-B04 — Generic independent acceptance is missing

- **Affected component:** Canary acceptance and product mission profiles.
- **Location:** [canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:4206), [authoring.py](/home/stris/work/agent-os-capsule-integration/admissible/product_launcher/authoring.py:502), [authoring.py](/home/stris/work/agent-os-capsule-integration/admissible/product_launcher/authoring.py:636).
- **Observed:** Canary acceptance recognizes only exact `CANARY.txt`. The golden product evaluator is tied to workflow recovery; the general template checks Git status and declares `OBSERVED_ONLY`.
- **Expected:** One model-independent evaluator capable of testing task requirements, repository state, omissions, out-of-scope changes and false completion.
- **Why it matters:** Claimed completion cannot be turned into comparable task-success evidence.
- **Confidence:** **Proven**.
- **Validation:** Seed deliberately incomplete, over-scoped and falsely claimed outputs and require deterministic refusal.
- **Bounded repair:** Introduce a benchmark-specific, frozen acceptance manifest and evaluator shared by A and B.

## Major

### AUD-MJ01 — Production paths are one-shot, not genuinely long-running

- **Affected component:** Mission profiles, product control plane, canary launcher.
- **Location:** [mission_profile.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/mission_profile.py:69), [configuration.py](/home/stris/work/agent-os-capsule-integration/admissible/product_launcher/configuration.py:92), [control.py](/home/stris/work/agent-os-capsule-integration/admissible/product_service/control.py:1).
- **Observed:** One provider attempt, one native attempt, zero retries/repairs, one process, one commit, maximum 3,600 seconds, in-memory active control state.
- **Expected:** Bounded multi-invocation sessions, checkpointing, pause/resume, budget exhaustion, restart and stale-state handling.
- **Importance:** A multi-hour engineering task is likely to hit context, process or dependency boundaries.
- **Confidence:** **Proven**.
- **Validation:** Multi-session provider-free soak with forced process death and controller restart.
- **Repair:** Add durable task/session state and explicit continuation authorization.

### AUD-MJ02 — Privileged owner authority is disconnected from the current product

- **Affected component:** Product authorization and owner broker.
- **Location:** [preflight.py](/home/stris/work/agent-os-capsule-integration/admissible/product_launcher/preflight.py:199), [records.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/records.py:137).
- **Observed:** Product uses `SHA256(phrase || NUL || payload)` inside the same product process. The broker’s root-generated record identity and signed receipt are used only by the canary.
- **Expected:** External, independently rooted authorization for the actual future run.
- **Importance:** The current product does not demonstrate the strongest intended “model proposes; Admissible authorizes” separation.
- **Confidence:** **Proven**.
- **Validation:** Import/call graph plus a negative run showing product execution cannot begin without a real broker receipt.
- **Repair:** Bind product launch to the privileged broker receipt and remove self-rooted production authorization.

### AUD-MJ03 — Authorization expiry is ineffective or absent

- **Affected component:** Product preparation store and privileged pending authorization.
- **Location:** [preflight.py](/home/stris/work/agent-os-capsule-integration/admissible/product_launcher/preflight.py:215), [state.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/owner_authority/state.py:199).
- **Observed:** `PreparationStore.expire()` never uses its clock or TTL and only removes records when `_order > max`, while creation refuses at `>= max`. A broker record remains launchable indefinitely in `PROVISIONED_PENDING`.
- **Expected:** Enforced expiry, explicit cancellation/revocation, and fail-closed stale authorization handling.
- **Importance:** A delayed launch can execute against stale owner intent or environmental assumptions.
- **Confidence:** **Proven**.
- **Validation:** Frozen-clock boundary tests and broker tests before/at/after expiry and cancellation.
- **Repair:** Implement expiry in the payload/state machine and signed verification contract.

### AUD-MJ04 — Initial-state and environment authority are incomplete

- **Affected component:** Launcher preflight and comparative setup.
- **Location:** [configuration.py](/home/stris/work/agent-os-capsule-integration/admissible/product_launcher/configuration.py:116), [pyproject.toml](/home/stris/work/agent-os-capsule-integration/pyproject.toml:1).
- **Observed:** Product preflight checks only `git rev-parse HEAD`. It does not bind dirty/untracked files, dependency closure, environment, toolchain, caches or network policy. There is no dependency lock.
- **Expected:** A common immutable source/environment manifest for both conditions.
- **Importance:** Different initial states can dominate outcome differences.
- **Confidence:** **Proven**.
- **Validation:** Mutate each omitted input while holding HEAD constant and require preflight refusal.
- **Repair:** Add a closed initial-state manifest and produce two isolated copies from it.

### AUD-MJ05 — Evidence and resource instrumentation are asymmetric

- **Affected component:** Product evidence, direct metrics, package-bin transport.
- **Location:** [frontier_comparison_metrics.py](/home/stris/work/agent-os-capsule-integration/admissible/runner/frontier_comparison_metrics.py:134), [native_executor.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/native_executor.py:2471).
- **Observed:** A has operator assertions; B has structured evidence. Neither provides token/cost, CPU/RSS or monotonic resource accounting; package-bin tool internals are not authoritative receipts.
- **Expected:** Common observational evidence plus governance-only additional evidence.
- **Importance:** Resource use, retries and behavior would not be comparable.
- **Confidence:** **Proven**.
- **Validation:** Schema completeness and reconciliation test over paired synthetic runs.
- **Repair:** Add an external observation layer and a common terminal resource manifest.

### AUD-MJ06 — Long output is retained in an unbounded queue

- **Affected component:** Managed process supervision.
- **Location:** [managed_process.py](/home/stris/work/agent-os-capsule-integration/admissible/managed_process.py:718), [managed_process.py](/home/stris/work/agent-os-capsule-integration/admissible/managed_process.py:1165).
- **Observed:** `_StreamPump` uses unbounded `Queue()` and enqueues every line. `run_managed_oneshot` waits without draining that queue. An isolated diagnostic produced 50,001 queued lines despite a 1,010-character retention cap.
- **Expected:** Bounded memory independent of total child output.
- **Importance:** Multi-hour build/test logs can exhaust the controller.
- **Confidence:** **Proven**.
- **Validation:** Multi-gigabyte stdout/stderr soak with bounded RSS.
- **Repair:** Do not queue lines on the one-shot path, or continuously drain into a bounded structure.

### AUD-MJ07 — Source, platform and operational entry points are ambiguous

- **Affected component:** Release/install process.
- **Location:** [README.md](/home/stris/work/agent-os-capsule-integration/README.md:75), [pyproject.toml](/home/stris/work/agent-os-capsule-integration/pyproject.toml:16), [mission_profile.py](/home/stris/work/agent-os-capsule-integration/admissible/delegated_gate/mission_profile.py:2545).
- **Observed:** The product checkout and installed canary use different detached commits; the product is not installed. Import fails on Linux because a Windows path is validated at import time. The provisioner console entry point is declared but unavailable.
- **Expected:** One supported, installed artifact set with verifiable commands on the chosen experiment host.
- **Importance:** An operator currently has to reconstruct which source and invocation to use.
- **Confidence:** **Proven**.
- **Validation:** Clean-host offline install and `--help`/read-only preflight smoke.
- **Repair:** Freeze a supported host, artifact manifest and operator entry points.

## Moderate

### AUD-MD01 — Tests do not prove the exact installed production path

- **Affected component:** Test suite and release validation.
- **Location:** [capsule host tests](/home/stris/work/agent-os-canary-preflight-v3/tests/test_admissible_capsule_host_codex_e2e.py:573), [owner tests](/home/stris/work/agent-os-canary-preflight-v3/tests/test_admissible_capsule_owner_rooted_witness_trust.py:540), [native tests](/home/stris/work/agent-os-canary-preflight-v3/tests/test_admissible_delegated_gate_native_executor.py:890).
- **Observed:** Negative coverage is extensive but mostly synthetic/provider-free. V18 crosses physical bind consumers but does not launch. The current host lacks pytest, and product import fails before tests can collect.
- **Expected:** Offline tests crossing installed launcher, broker protocol, disposable root state, process boundary and evaluator.
- **Importance:** Passing unit tests do not prove connection.
- **Confidence:** **Proven**.
- **Validation:** Hermetic installed-artifact integration suite.
- **Repair:** Add it as a release gate; retain current unit tests.

### AUD-MD02 — “Two independent copies” re-read the same root

- **Affected component:** Canary verification.
- **Location:** [canary_launch.py](/home/stris/work/agent-os-canary-preflight-v3/admissible/capsule/canary_launch.py:4271).
- **Observed:** Checkpoint and behavior passes have different logical copy IDs but both call `_read_canary_material(accepted_root)` on the same physical directory.
- **Expected:** Either two independently materialized copies or a narrower claim of two independent reads.
- **Importance:** The evidence overstates physical independence, though exact-byte acceptance remains strong.
- **Confidence:** **Proven**.
- **Validation:** Alter one separately copied tree and prove disagreement is detected.
- **Repair:** Make physical copies or correct the evidence vocabulary.

### AUD-MD03 — Prior comparative completion is not supported by located evidence

- **Affected component:** Historical comparison archive.
- **Location:** [protocol](/home/stris/work/agent-os-capsule-integration/docs/admissible-frontier-model-comparison-protocol.md:186), [initial report](/home/stris/work/agent-os-capsule-integration/benchmark/reports/admissible_frontier_model_comparison_initial.md:1).
- **Observed:** The preserved report says Condition B completed with operator corrections, Condition A was pending/not created, and the result was not autonomous long-running success. No later A artifact was found.
- **Expected:** A terminal paired manifest if a later comparison completed.
- **Importance:** Historical results must not seed assumptions or contaminate the next experiment.
- **Confidence:** **Strongly indicated**; evidence may exist outside the inspected physical scope.
- **Validation:** Supply and hash any external paired archive, or record the claim as unverified.
- **Repair:** Reconcile historical provenance without recreating missing results.

### AUD-MD04 — Live owner-service health could not be independently established

- **Affected component:** Installed systemd owner authority and current witness.
- **Location:** `/etc/admissible-owner-authority-v1/installation-v1.json`, `/run/admissible-owner-authority-v1/pending-authorization-witness.v1.json`.
- **Observed:** Installation and witness bytes are present and internally consistent. The audit sandbox remaps root-owned files to `nobody` and cannot access the systemd bus, so live ownership/service assertions cannot be rechecked faithfully.
- **Expected:** Read-only host-native health attestation before later planning.
- **Importance:** This is an unresolved audit-environment limitation, not proven system corruption.
- **Confidence:** **Unresolved**.
- **Validation:** Run the existing non-mutating host readiness/status surface outside UID remapping.
- **Repair:** None unless that verification fails.

## Minor

### AUD-MN01 — Obsolete installed launcher remains alongside the bound launcher

- **Affected component:** `/opt` installation.
- **Location:** `/opt/admissible-capsule-canary-launcher-v1`, `/opt/admissible-capsule-canary-launcher-v6`.
- **Observed:** Two launcher artifacts exist; only v6 is bound by the recovered preparation.
- **Expected:** Operators should not be able to confuse obsolete and authoritative copies.
- **Importance:** Operational ambiguity, not an authority bypass because hashes and paths are bound.
- **Confidence:** **Proven**.
- **Validation:** Read-only release inventory.
- **Repair:** Label/deprecate in readiness output; do not delete during this audit.

### AUD-MN02 — Historical documentation names a session path that is not the tracked artifact

- **Affected component:** Comparison documentation.
- **Location:** [comparison protocol](/home/stris/work/agent-os-capsule-integration/docs/admissible-frontier-model-comparison-protocol.md:131).
- **Observed:** Documentation cites `.admissible/live_rehearsal_027b_session/session.json`; the located tracked export is `benchmark/live_rehearsal_workspace_027b/session_export_027b.json`.
- **Expected:** Archival paths resolve to the preserved object.
- **Importance:** Adds third-party reconstruction friction.
- **Confidence:** **Proven**.
- **Validation:** Archive manifest reconciliation.
- **Repair:** Correct documentation during a future authorized repair.

## Observation

### AUD-O01 — V18 recovery is genuine and correctly stops short of execution

- **Affected component:** V18 recovery.
- **Evidence:** [terminal pointer](/home/stris/work/admissible-capsule/canary-preflight-v18/recovery-evidence/V18_RECOVERY_TERMINAL_POINTER.json), [bind report](/home/stris/work/admissible-capsule/canary-preflight-v18/recovery-evidence/v18-recovery-world/bind-report.v18-recovery-bind-attempt-1.json:546).
- **Observed:** Production authority is true; final generation, bind state and witness binding are durable; no model, provider, Docker, run-root or owner-authorization action occurred during bind.
- **Expected:** Exactly this bounded recovery outcome.
- **Importance:** This is a reusable authority-chain proof, not experiment completion.
- **Confidence:** **Proven** by terminal hashes and full generation hash verification.
- **Validation:** Continue using read-only status/integrity checks only.
- **Recommendation:** Preserve without rerunning or repurposing.

### AUD-O02 — Absence of an OS sandbox in the product is explicitly documented

- **Affected component:** Modern product threat model.
- **Evidence:** [README.md](/home/stris/work/agent-os-capsule-integration/README.md:216).
- **Observed:** Same-user tampering and unrestricted host filesystem/network are declared non-claims.
- **Expected:** If this product path is selected, the experiment must report this rather than treating prompt restrictions as preventive confinement.
- **Importance:** The limitation is not hidden, but it changes what governance conclusions can be drawn.
- **Confidence:** **Proven**.
- **Validation:** Include threat-model fields in the frozen experiment protocol.
- **Recommendation:** Do not silently reinterpret post-observation as per-action authorization.

# 7. Existing strengths

- V18’s terminal pointer, bind report, final-generation ledger and hashes form a coherent, durable chain of custody.
- The privileged owner authority has a narrow broker protocol, root-generated record identity, exact payload binding, Ed25519 receipts and forward-only one-shot consumption.
- The canary launcher performs all pre-effect checks before owner consumption and records ambiguous post-consumption failures rather than retrying.
- Pinned Codex identity, model fallback refusal, app-server schema binding, runtime dependency authority and descriptor-based confinement are materially strong.
- The canary dynamic-tool grammar prevents native Codex capabilities from silently widening the effect surface.
- Process cleanup, timeout, crash and orphan-child behavior have substantial negative-test coverage.
- Intake, provider claims, process status, verification and final acceptance are separate evidence concepts.
- The product read model fails closed on absent, malformed or inconsistent evidence rather than fabricating success.
- All inspected Git worktrees were clean, and installed canary source matched its authoritative source module.
- V15–V18 one-shot identities and terminal states provide clear accidental-rerun protections.

# 8. Bounded repair set

## Mandatory repairs

1. Freeze one authoritative commit, supported host, build process and installed-artifact manifest.
2. Define a single paired execution harness with a direct mode and a governed mode around the same pinned model executable.
3. Connect the governed mode to the privileged owner broker and a generic, preventive action/effect boundary.
4. Add durable multi-invocation task state, checkpointing, cancellation, restart and bounded continuation.
5. Define a benchmark-specific mission/authority payload and generic independent acceptance evaluator.
6. Bind prompt bytes, initial repository state, dependencies, environment, tool grammar, model, executable, budgets, network policy and evaluator into the run authority.
7. Implement authorization expiry/cancellation and fix the product preparation TTL defect.
8. Replace the unbounded process-output queue and add long-output soak coverage.
9. Create two isolated initial workspaces from one immutable snapshot with independent caches and no shared mutable authorization/session state.
10. Add common A/B observation and resource evidence outside the causal governance intervention.

## Mandatory validation

- Provider-free exact installed-path integration in disposable roots.
- Negative matrix for wrong executable/source/prompt/tools/budget/model/witness, replay, duplicate action, stale state, partial publication and malformed receipts.
- Restart/crash tests at every durable transition.
- Large-log, long-duration and budget-exhaustion soak tests.
- False-completion, omitted-requirement and out-of-scope mutation acceptance tests.
- Mechanical A/B equality gate for every non-governance input.
- Host-native read-only owner service and witness readiness verification.
- Reproducible clean-host offline installation test.

## Desirable improvements

- One readiness report explaining which commands are read-only, provider-contacting, authority-creating or mutating.
- Counterbalanced or randomized condition order.
- Machine-readable historical archive index and deprecation labels for obsolete artifacts.
- Corrected “independent copies” terminology or separate physical verification copies.

## Out of scope

- Rerunning V15, V16, V17 or V18.
- Reusing or authorizing the recovered V14 canary for the benchmark.
- Minting, refreshing the witness, launching a provider, or selecting the final benchmark.
- Inventing another version number.
- Wholesale replacement of the owner broker, canary ledger or read-model design.

# 9. Candidate benchmark archetypes

| Archetype | What it tests and evaluation | Duration | Risks | Current support |
|---|---|---:|---|---|
| Offline multi-module CLI/library extension | Planning, API design, refactoring, migration, tests and debugging. Evaluate with public tests, held-out property tests, repository-scope diff and reproducible CLI scenarios. | 2–6 hours | Model may need dependency changes; hidden tests must avoid leakage | Not yet: needs multi-session execution and generic acceptance |
| Offline workflow/state-machine repair | Implement persistence, crash recovery, concurrency cases and backward-compatible schema migration in a seeded repository. Evaluate through deterministic fault injection, restart tests and invariant checking. | 3–8 hours | Flaky concurrency tests; evaluator must distinguish valid alternative designs | Good conceptual fit for Admissible evidence, but current one-shot path is insufficient |
| Local parser/compiler or data-transformation feature | Add a substantial language/data feature across parser, validation, serialization, CLI and documentation. Evaluate with golden fixtures, fuzz/property tests, round trips and out-of-scope diff checks. | 2–5 hours | Overfitting to visible fixtures; large generated corpora | Suitable once dependencies, log handling and shared evaluator are frozen |

All three can be credential-free, network-free, initialized from identical Git snapshots and independently verified. None should be selected until the physical execution and comparison architecture is fixed.

# 10. Proposed next planning inputs

Before an implementation and execution plan can be frozen, obtain or decide:

1. The authoritative repository commit and supported host platform.
2. The exact installed build manifest and executable digests.
3. The one model, model version, reasoning configuration and session-continuation semantics.
4. Byte-exact task prompt and delivery protocol.
5. Exact initial repository snapshot, dirty-state policy and dependency/toolchain lock.
6. Direct and governed tool grammars, with a precise definition of the governance intervention.
7. Network, filesystem, shell, Git and dependency-install authority for each condition.
8. Time, token/cost, process, retry, continuation and human-intervention budgets.
9. Durable task, checkpoint, recovery and cancellation schemas.
10. Future owner payload fields, expiry, revocation and unused-authorization handling.
11. Shared observational evidence schema and governance-only additional evidence.
12. Generic acceptance specification, public tests, held-out tests and scope-diff policy.
13. Workspace/cache/session isolation and condition-order procedure.
14. Refusal and terminal-state taxonomy.
15. Provider-free release validation results for the exact installed path.
16. Reconciliation or explicit retirement of the unverified prior Condition A claim.

# 11. Final audit checklist

- [x] No source code modified.
- [x] No installed artifact modified.
- [x] No governed or preserved evidence modified.
- [x] No owner authorization created or published.
- [x] No Codex, Cursor, or other model launched.
- [x] No model provider or external service contacted.
- [x] No mint or remint created.
- [x] No witness bound, replaced, or refreshed.
- [x] No governed run or benchmark task executed.
- [x] No V15, V16, V17, or V18 one-shot action rerun.
- [x] No release or new version created.