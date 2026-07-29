# Admissible

Admissible is a local developer tool for governed delegation to coding agents.
An operator defines a bounded mission, reviews the exact execution contract,
authorizes it, runs a compatible native coding agent, and receives an
evidence-backed result in a browser UI.

An agent's completion message is a claim. Admissible authorizes a bounded
mission, captures execution evidence, independently reconstructs the result,
and accepts or refuses the run based on that evidence.

Admissible does not make agents reliable, formally verify arbitrary software,
provide an OS sandbox, or treat an agent's own success message as proof.

## OpenAI Build Week submission

The judge-facing product is:

```text
admissible/product_launcher/
admissible/product_service/
admissible/product_ui/
admissible/product_read_model/
admissible/delegated_gate/
```

Historical Agent OS code, V0 controllers, benchmark materials, reports, and
earlier demonstrations remain in this repository for provenance and regression
coverage. They are not the judge-facing execution path. In particular, the
historical `agent-os` console script remains supported but does not launch the
Admissible product UI.

## What the operator does

1. Enter a goal.
2. Receive a structured mission proposal.
3. Review and authorize the frozen contract.
4. Launch the coding agent within that authority.
5. Capture checkpoint, Git, workspace, and behavioral evidence.
6. Reconstruct the result independently from persisted evidence.
7. Refuse unsupported completion claims or present an evidence-backed accepted
   result.
8. Inspect the evidence and final workspace through the browser UI.

The incident-replay workflow demonstrates why the final two steps are separate
from agent execution. The agent claims completion in both attempts. The first
run is refused because replay behavior is inconsistent with the required
behavior. The corrected run is accepted only after the required behavior and
the independently reconstructed evidence agree. Provider-free tests reproduce
these authority outcomes with deterministic fixtures; they do not pretend to
reproduce a real provider execution.

## Architecture

```text
Browser UI
  -> authenticated loopback product service
  -> product launcher and frozen authorization contract
  -> governed native child execution
  -> checkpoint and evidence capture
  -> independent product read model
  -> authoritative accepted/refused presentation
```

The model proposes work. The owner grants bounded authority. The native child
executes under that contract. Evidence records what happened. The product read
model reconstructs the outcome without trusting the child's completion claim.
The final disposition shown to the owner comes from that reconstruction, not
from the model proposal or agent output.

Mission profile v2 and authorization payload V4 are active authority contracts
for the verified workflow template. Compatibility schemas remain in the tree
for historical evidence and fail-closed loading.

## Supported platform and prerequisites

Primary supported platform: **Windows**.

Validated environment:

- Python 3.12
- Git 2.45
- Node.js 22
- npm 10

The package declares Python 3.10 or newer, but the final product flow was
validated on Windows with Python 3.12. Linux and macOS are not currently claimed
as validated product platforms.

Provider-free tests and UI smoke require:

- Python 3.10+
- Git
- Node.js and npm for the behavioral/UI test paths
- pytest, installed by the `test` extra

A real governed execution additionally requires:

- an available compatible coding-agent executable;
- successful local executable attestation;
- an environment-specific source repository and exact source HEAD;
- separate run and contract-document directories;
- owner review and authorization.

Provider availability and provider authentication are external to Admissible.

## Fresh-clone installation

```powershell
git clone https://github.com/Camarade-dev/agent-os.git
cd agent-os

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install ".[test]"

admissible --help
python -m admissible.product_launcher --help
agent-os --help
```

`admissible` and `python -m admissible.product_launcher` invoke the same final
launcher. `agent-os` is retained for compatibility with the historical Agent OS
CLI.

## Judge-facing provider-free path

### 1. Start the local UI without a provider

From the repository root in the activated virtual environment:

```powershell
$source = (Resolve-Path .).Path
$head = (git rev-parse HEAD).Trim()
$smoke = Join-Path $env:TEMP "admissible-judge-smoke"

admissible `
  --source-repository "$source" `
  --required-source-head "$head" `
  --run-parent "$smoke\runs" `
  --contract-documents-directory "$smoke\contracts" `
  --executable "definitely-not-a-provider" `
  --attestation-class package-bin `
  --authorization-mode PRECOMMITTED_DIGEST
```

The launcher prints a URL such as `http://127.0.0.1:<ephemeral-port>/`. Both
product HTTP planes bind to `127.0.0.1`; port `0` selects free ephemeral ports.
The UI can compose and review a mission without a provider. Preparing execution
with the deliberately nonexistent executable must terminate in a safe
`BLOCKED` preflight state because local capability attestation is unavailable;
it must not create a governed run or invoke a provider. Stop the launcher with
`Ctrl+C`.

### 2. Run the quick deterministic authority check

Use a short Windows temporary path to avoid nested-Git path-length failures:

```powershell
New-Item -ItemType Directory -Force C:\abw | Out-Null
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONHASHSEED = "0"

python -m pytest -p no:cacheprovider --basetemp C:\abw\quick -q -ra `
  tests/test_admissible_product_launcher_g2_5.py::test_golden_preparation_payload_and_launch_both_modes `
  tests/test_admissible_product_service.py::test_http_start_is_202_and_second_active_is_409 `
  tests/test_admissible_product_read_model.py::test_refused_before_behavioral_verification `
  tests/test_admissible_product_read_model.py::test_verified_authoritative_verdict `
  tests/test_admissible_product_ui_g4.py::test_result_evidence_and_transport_return_code_are_separate `
  tests/test_admissible_behavioral_backend_authority_consistency.py::test_blocking_backend_drift_classes_remain_refused_with_truthful_terminal
```

This provider-free set covers compose/authorize boundaries, product-service
lifecycle, authoritative accepted/refused reconstruction, browser result
presentation, and behavioral/backend authority consistency. Submission
verification produced `11 passed` for this quick command.

A broader provider-free selection covering the launcher, service, read model,
G1 integration, G3/G4 UI, workflow-recovery profile, behavioral/backend
authority consistency, native checkpoint acceptance, and governed rerun
produced:

```text
74 focused product and authority tests passed without invoking a provider.
```

## Real governed execution

The launcher entry points are:

```text
admissible
python -m admissible.product_launcher
```

The environment-specific form is:

```powershell
admissible `
  --source-repository "<absolute-source-repository>" `
  --required-source-head "<exact-lowercase-Git-object-id>" `
  --run-parent "<absolute-run-parent>" `
  --contract-documents-directory "<separate-absolute-directory>" `
  --executable "<attested-compatible-agent-executable>" `
  --attestation-class "<package-bin-or-wrapper-chain>" `
  --authorization-mode INTERACTIVE_BOUND_CONFIRMATION
```

The mission/template, workspace fixture, backend attestation, model selection,
timeouts, and owner authorization must match the intended run. Never place an
owner authorization phrase, authorization digest, capability token, or API key
in source control or command history. This repository does not bundle a
portable real-provider execution.

## Security boundary and limitations

The final product implements:

- exact loopback-only product HTTP binding;
- Host and Origin validation;
- CSRF and capability-token boundaries;
- Content Security Policy, `no-store`, and content-type hardening;
- bounded request and output handling;
- frozen mission, source, and authorization identities;
- independent evidence reconstruction before an authoritative disposition.

Important limits:

- Admissible does not provide an OS-level filesystem or network sandbox.
- Local same-user processes are not a cryptographic adversarial boundary and
  can potentially tamper with resources available to that user.
- Admissible does not make arbitrary agent output correct.
- A completion claim can be refused when required evidence is missing,
  inconsistent, or invalid.
- Windows is the currently verified product platform.
- Provider availability, provider behavior, and provider credentials remain
  external dependencies.

## What was built during OpenAI Build Week

### Pre-existing work

The repository predates the submission period. Pre-existing work includes:

- the Agent OS protocol and CLI;
- the early Admissible thesis and action-admission research;
- benchmark schemas, cases, scoring material, and prior research artifacts.

These materials are retained to make the lineage inspectable; they are not
presented as newly created Build Week product work.

### Added or meaningfully extended during July 13-21, 2026

Verified Git history records:

- bounded governed execution (`decf0a3`, `e70c287`);
- the delegated gate and native executor (`1396467`, `ab8b47d`);
- executable attestation and owner authorization payloads (`e5b267f`,
  `6ee8293`);
- checkpoint, evidence reconstruction, and acceptance (`4805479`, `faac579`);
- the Build Week evidence replay (`d62e1ea`);
- native mission execution (`51a4c50`);
- independent product read model and authoritative reconstruction (`692c3e1`,
  `15eb739`, `e57d0b4`);
- authenticated loopback product service (`911adec`);
- contract authoring and browser-safe launcher (`d3b5a0e`);
- browser compose/authorize flow (`be8ed07`);
- browser result/evidence flow (`b2a20ed`);
- verified incident-replay workflow (`c3dd831`);
- governed rerun recovery (`226eb07`);
- final behavioral/backend authority consistency (`16e7024`).

This list is representative. It does not claim that every historical file in
the repository was created during Build Week.

## Codex and GPT-5.6 collaboration

Codex was used throughout the Build Week implementation and verification
process. GPT-5.6 was used in the final submission-hardening session to:

- perform an adversarial repository audit;
- identify the wrong public source and stale product narrative;
- repair installable UI packaging;
- prepare the judge-facing repository documentation;
- run provider-free verification.

This README does not attribute earlier implementation work to GPT-5.6 without
an identified session. The submission form contains the `/feedback` Session ID
for the primary core build thread; no unknown or fabricated Session ID is
stored here.

## Repository map

```text
admissible/
  product_launcher/     final CLI, preflight, authorization and child launch
  product_service/      authenticated loopback product control plane
  product_ui/           source-controlled browser UI
  product_read_model/   independent evidence reconstruction and presentation
  delegated_gate/       mission profiles, executor, checkpoints and evidence

tests/
  test_admissible_product_*       final product and UI coverage
  test_admissible_workflow_*      trusted workflow profile coverage
  test_admissible_v0_*            historical regression coverage

benchmark/
  schemas, fixtures, reports and earlier demonstration material

agent_os/
  historical Agent OS protocol and CLI package

docs/
  current architecture, security, protocol, and historical documentation
```

The trusted workflow profile and local fixture registry live under
`admissible/delegated_gate/`. Historical evidence and reports are test or
provenance inputs, not runtime authority merely because they are present.

## Further technical documentation

- [Host Codex app-server / capsule-effect backend v1](docs/admissible-host-codex-capsule-backend.md)

- [Native executor and authority boundary](docs/admissible-native-executor-canary.md)
- [Build Week read-only evidence replay](docs/admissible-build-week-demo.md)
- [Admissible thesis](docs/Admissible_THESIS.md)
- [Agent OS lineage boundary](docs/admissible-agent-os-lineage.md)

## License

Admissible and the retained repository materials are distributed under the
[MIT License](LICENSE).
