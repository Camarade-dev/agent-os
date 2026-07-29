# Host Codex app-server / capsule-effect backend v1

## Status and claim boundary

`HostCodexAppServerCapsuleBackend` is the concrete Linux backend for an
authenticated Codex control process outside a sealed execution capsule. The
provider-free witness uses a synthetic Codex 0.145.0 event source and real
local Docker capsules. It never invokes a model or provider and is not a real
Neon Relay acceptance.

The backend produces only a frozen, untrusted, non-Git `ProviderOutput`.
Acceptance remains a separate sequence:

```text
authenticated Codex app-server control process
  -> pinned dynamicTools requests
  -> durable trusted controller
  -> sealed Docker capsule effects
  -> frozen untrusted provider-output tree
  -> CanonicalIntake
  -> canonical AcceptedMaterialIdentity
  -> independent checkpoint copy of that material
  -> independent behavioral copy of that material
  -> durable finalization preparation
  -> AdmissibleFinalizer compare-and-swap
  -> accepted Git commit
```

No app-server or capsule code can stage, commit, update a ref, or publish.
`CanonicalIntake`, independent verification, and `AdmissibleFinalizer` remain
distinct downstream authorities.

## Authorities and trusted computing base

The implementation keeps these identities separate:

- `CapsuleAuthority` binds the generic backend, image identity, and mission.
- `AuthenticatedControlAuthority` binds Codex 0.145.0 executable identity to
  the bwrap policy. It refers to login/configuration locations but never reads,
  copies, serializes, or hashes their contents.
- `CapsuleExecutionAuthority` binds the image and Docker security limits.
- `DurableControllerAuthority` binds the closed dynamic-tool set to
  request-before-effect durability and exactly-one-result pairing.
- `IntakeAuthority` defines the exact allowed output byte namespace.
- `AcceptedMaterialIdentity` binds the intake authority, exact sorted path
  set, regular-file modes, accepted byte hashes, accepted manifest
  fingerprint, and final published intake-evidence fingerprint.
- checkpoint and behavioral verifier identities remain independent.
- `FinalizerAuthority` binds the exact bare repository, publication ref,
  closed Git environment policy, and finalizer-owned evidence store.
- `AdmissibleFinalizer` alone owns the accepted Git ref transaction.

The trusted computing base is the Linux kernel and bubblewrap isolation,
Docker daemon/runtime and the pinned capsule image, the Python controller and
durable session store, canonical intake, independent verifiers, finalizer, and
Git used by the finalizer. Codex/model output, app-server event contents,
dynamic-tool arguments, capsule processes, and the frozen provider workspace
are untrusted.

The host controller necessarily has local Docker client authority. Neither
the Codex control process nor the capsule receives the Docker socket.

## Pinned Codex 0.145.0 protocol

The production connection is newline-delimited JSON-RPC-like app-server
messages over stdio, with the `jsonrpc` field omitted as specified by Codex
0.145.0.

The client sends:

1. `initialize` with client identity and
   `capabilities.experimentalApi = true`;
2. `initialized` notification;
3. `thread/start` with:
   - `cwd = "/control/empty"`;
   - `approvalPolicy = "never"`;
   - `sandbox = "readOnly"`;
   - `ephemeral = true`;
   - `environments = []`, `runtimeWorkspaceRoots = []`, and
     `selectedCapabilityRoots = []`;
   - the single `capsule_effects` dynamic-tools namespace;
4. `turn/start` with the returned `threadId` and mission text.

The only effect request accepted from the server is:

```json
{
  "method": "item/tool/call",
  "id": 60,
  "params": {
    "threadId": "thread-id",
    "turnId": "turn-id",
    "callId": "call-id",
    "namespace": "capsule_effects",
    "tool": "write_file",
    "arguments": {
      "path": "index.html",
      "content": "<html></html>\n",
      "operation": "create"
    }
  }
}
```

The client replies only after durable request evidence and capsule execution:

```json
{
  "id": 60,
  "result": {
    "contentItems": [
      {
        "type": "inputText",
        "text": "{\"classification\":\"SUCCEEDED\",\"exitCode\":0,\"stderr\":\"\",\"stderrTruncated\":false,\"stdout\":\"\",\"stdoutTruncated\":false,\"timedOut\":false}"
      }
    ],
    "success": true
  }
}
```

The namespace contains exactly four functions:

- `list_files(path, max_depth)` lists a relative subtree with depth 1–8.
- `read_file(path)` reads one bounded regular workspace file.
- `write_file(path, content, operation)` accepts `create`, `replace`, or
  `upsert` and bounded UTF-8 content.
- `run_command(argv, cwd, timeout_ms)` executes a bounded argv vector in a
  relative capsule workspace directory.

All schemas set `additionalProperties: false`. Runtime validation additionally
bounds canonical argument bytes, path bytes, argv count and bytes, file bytes,
stdout/stderr, per-command wall time, session wall time, file count, and output
tree bytes. Absolute paths, `..`, `.git` path requests, symlink escapes, unknown
namespaces, and unknown tools refuse.

Every request identity binds session, monotonically increasing sequence,
JSON-RPC ID, call ID, thread, turn, namespace, tool, and canonical arguments.
The store refuses:

- an exact repeated RPC/call identity as `DUPLICATE_TOOL_ID_REFUSED`;
- either ID reused with different binding or arguments as
  `CONFLICTING_TOOL_ID_REFUSED`;
- a second result for one request;
- a result with no request or another request fingerprint.

Native `commandExecution`, `fileChange`, `mcpToolCall`, or any other
non-passive item fails the session closed. Unknown server requests, shell
methods, command/file deltas, turn diffs, approval requests, MCP effects,
process spawning, and future unknown methods also fail closed. Historical
protocol parsers are not reused as authority here.

## Host bwrap boundary

`HostControlBwrapPolicy` starts from an empty mount namespace. It creates only
private `/proc`, `/dev`, `/tmp`, `/runtime`, and `/control` locations, then
read-only binds:

- one exact Codex executable at `/runtime/codex`;
- the login location at `/control/codex-home/auth.json`;
- optional configuration at `/control/codex-home/config.toml`;
- optional exact certificate, resolver, and hosts files.

It sets a private home, `CODEX_HOME`, and empty cwd, clears the inherited
environment, creates a new session/PID namespace, dies with its parent, and
shares only host networking required for provider access.

It does not bind `/`, `/home`, `/bin`, `/usr/bin`, a host shell, provider
workspace, source repository, historical run, spike artifact, intake tree,
verification copy, finalizer repository, unrelated home, or Docker socket.
Policy construction validates that every allowed source is outside configured
forbidden roots. Durable evidence contains destinations and booleans, not auth
source paths or contents.

The provider-free bwrap witness compiles one static synthetic process. It uses
only `access(2)` to confirm that the synthetic auth *location* and empty cwd
exist while the capsule workspace, forbidden host workspace, host shell, and
Docker socket do not. It does not read the synthetic placeholder bytes.

## Docker capsule boundary

The controller starts one disposable container with:

```text
--init
--user <non-root-uid>:<non-root-gid>
--read-only
--cap-drop ALL
--security-opt no-new-privileges:true
--network none
--cpus 0.50
--memory 256m
--memory-swap 256m
--pids-limit 64
--ulimit nofile=256:256
--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
--mount type=bind,src=<controller-private-disposable-dir>,dst=/workspace
--workdir /workspace
--env HOME=/nonexistent
--env CODEX_HOME=/nonexistent
```

No environment credential is forwarded. No login/config path, external
network, Git repository, or Docker socket is mounted. Fixed controller-owned
shell snippets implement guarded list/read/write operations; requested shell
commands run only through `docker exec` in `/workspace`.

On timeout or output overflow, the controller kills the whole container rather
than assuming the Docker CLI termination killed descendants. Final cleanup
force-removes and then proves absence of the container, which reaps the init
process and all descendants, and removes the disposable bind workspace. A
trusted read-only freeze copies bounded output without following symlinks into
the separate untrusted output-intake area.

## Durable session evidence and crash behavior

Each session directory contains an append-only `evidence.jsonl` and, after a
successful freeze transaction, `provider-output.json`. Every log record binds
its index and previous record fingerprint. Each append is locked, written,
and fsynced.

The log covers:

- capsule, authenticated-control, execution, controller, and workspace
  authority identities;
- Docker container/process identity;
- app-server process identity;
- bound thread and turn;
- canonical dynamic-tool request/result pairs;
- cleanup and complete process-tree evidence;
- frozen `ProviderOutput`;
- explicit provider-session terminal classification;
- the canonical accepted-material identity;
- checkpoint and behavioral results bound to that identity;
- durable finalization evidence and its read-back receipt;
- the exact finalization result.

`provider-output.json` is atomically published before its corresponding log
record. Reconstruction validates the complete hash chain, event ordering,
request/result pairing, protocol binding, output fingerprint, cleanup, and
terminal classification using evidence only.

If a crash occurs after a request fsync but before its paired result fsync,
reconstruction derives `CRASH_UNPAIRED_REQUEST`. It never assumes that the
effect failed, succeeded, or is safe to replay.

## Accepted-material continuity and publication

Canonical intake writes only truthful states. `CANDIDATE_VALIDATED` records a
completed observation, `PUBLICATION_PREPARED` records a fully fsynced staging
tree, `DESTINATION_RENAME_COMPLETED` is written only after the destination
rename and parent-directory fsync, and `ACCEPTED_INTAKE_PUBLISHED` is the only
state the reducer accepts. A crash between preparation evidence and rename
therefore leaves no accepted destination and no evidence claiming publication.

The checkpoint and behavioral verifier use separate private copies with
different copy IDs. Both copies must have the same root fingerprint: the
canonical accepted manifest fingerprint. Each result carries the complete
accepted-material identity, and its before/after byte hashes must equal that
root. A changed root, different material identity, or mutation refuses; a
checkpoint PASS never supplies a behavioral PASS.

Finalization first builds from `git read-tree --empty`, inserts exactly the
accepted paths, modes, and blobs, and recursively reads the resulting tree
back. The parent contributes ancestry only and cannot contribute a tree entry.
The prepared commit, exact tree, material identity, parent, publication ref,
and finalizer authority are written to a finalizer-owned evidence store and
read back before `update-ref`. The resulting typed durability receipt binds
the exact evidence bytes and exact destination. There is no caller-provided
durability boolean.

Every finalizer Git process receives a minimal explicit environment. System,
global, and XDG configuration are disabled; ambient `GIT_*` variables are not
inherited; replacement refs and alternate object directories are absent;
attributes and filters are neutralized; identity and timestamps are frozen;
and `core.hooksPath` points at a guaranteed empty finalizer-owned directory.
An update failure is classified as a compare-and-swap conflict only when the
ref actually changed; other Git failures remain operational failures.

## Compatibility

Historical ACP/Cursor implementation and fingerprints remain unchanged. That
code is retained as:

- historical backend support;
- protocol handling and defense in depth;
- not the root authority for the host-control/capsule backend.

The concrete backend records the repaired generic identity and verification
contracts without adding concrete transport authority to `CapsuleBackend` or
`ProviderOutput`.

## Provider-free witness versus remaining real canary

The checked-in witness proves controller and isolation behavior without a
provider. Its final commit is labeled synthetic and explicitly says it is not
Neon Relay. It is not evidence of real model quality, login viability, token
refresh behavior, or real mission acceptance.

A separately owner-authorized real canary still needs to:

1. attest the exact Codex 0.145.0 executable/package selected for production;
2. validate the exact login/config and TLS/DNS file set under bwrap without
   copying or inspecting login contents;
3. start one authenticated app-server through bwrap and confirm the pinned
   handshake/dynamic-tool stream against a deliberately bounded canary;
4. capture real process/network/cleanup evidence;
5. pass real independent checkpoint and behavioral verification before
   finalization.

That canary must use the existing ChatGPT/Codex login, not an API key. It must
not use a direct `/v1/responses` owner relay and must not be represented as
acceptance until all downstream stages pass.
