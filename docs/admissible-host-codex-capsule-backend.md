# Host Codex control / Docker capsule backend v1

## Readiness

The provider-free backend and all boundaries independent of authentication are
implemented. Production provider use is **not ready**.

`AuthenticationBoundary` is the closed integration point for the independent
authentication and service-egress architecture. The default
`PendingAuthenticationBoundary` mounts no authentication state, grants no
network, and refuses launch. This branch has no architecture-approved
`OS_ENFORCED` implementation: the policy rejects even a caller-defined
boundary that merely asserts that state, and its evidence always reports
`production_ready = false`. The parallel architecture result must add the
concrete implementation and its independent OS attestations before a
production connection can become constructible.

The checked-in `SyntheticAuthenticationBoundary` is only a network-isolated,
provider-incapable test fixture. It identifies its fixture with metadata
without opening or hashing its contents. It cannot be substituted for the
production result.

No provider output has acceptance, Git, verification, or publication
authority. The flow remains:

```text
Codex app-server control
  -> pinned dynamic-tool request
  -> durable request/effect boundary
  -> sealed Docker capsule
  -> content-addressed untrusted snapshot
  -> canonical intake
  -> accepted-material identity
  -> independent checkpoint and behavior evidence
  -> durable finalization evidence
  -> finalizer-owned Git transaction
```

## One execution authority

Each prepared backend session creates one immutable
`BackendExecutionAuthority`. It binds:

- the exact backend kind and Codex app-server protocol version;
- the complete packaged generated-schema identity;
- content and filesystem identities for the Codex, bwrap, and Docker
  executables, or source-derived identities for provider-free fixtures;
- the host-control policy and exact bwrap argv policy;
- controller identity, verified immutable capsule image ID, and exact
  `dynamicTools` schema;
- the complete initialize/thread/turn request-policy fingerprint, including
  experimental negotiation and preventive capability configuration;
- exact mission and prompt bytes plus their SHA-256 fingerprints;
- backend session and run identities, with controller session and capsule
  handle independently bound in every durable effect request;
- connection mode and connection-factory identity;
- authentication-boundary state;
- process, protocol, output, workspace, CPU, memory, PID, and time budgets;
- the terminal/draining policy.

Construction validates every cross-binding. Launch independently re-attests
the executable objects, source objects, control policy, connection factory,
Docker executable, image ID, and controller authority. Caller-provided display
strings are not component attestations. Backend kind, production/synthetic
mode, protocol, mission, prompt, policy, controller, image, or factory
substitution refuses before a provider effect.

## Codex 0.145.0 protocol

The package contains a hash-manifested subset of the locally generated
experimental Codex 0.145.0 app-server schemas. Every packaged file and the
complete source bundle identity are verified before use. JSON is decoded with
duplicate-key detection before semantic interpretation.

The client sends `initialize` with `capabilities.experimentalApi = true`, then
`initialized`. `thread/start` contains the exact request value:

```json
{
  "cwd": "/control/empty",
  "approvalPolicy": "never",
  "sandbox": "read-only",
  "ephemeral": true,
  "environments": [],
  "runtimeWorkspaceRoots": [],
  "selectedCapabilityRoots": []
}
```

The generated response schema represents the resulting policy as
`{"type":"readOnly","networkAccess":false}`; that response shape is distinct
from the request spelling.

Initialize, thread/start, thread/started, turn/start, turn/started,
item/started, item/tool/call, item/completed, turn/completed, and error
messages are phase-aware. Exact RPC, session, thread, turn, item, call,
namespace, tool, and argument identities are required. Unknown notifications,
native requests, malformed terminal records, ambiguous lifecycle records,
wrong-thread/turn terminals, and any record after terminal state refuse the
session.

A dynamic tool request is authorized only while its exact
`dynamicToolCall` item is active. The result is returned only after the
request and the effect-execution boundary are durable and the exact result is
paired. Failed and interrupted terminal paths require the generated terminal
fields.

After a nominal terminal notification, the controller drains a bounded number
of bounded-size records until process EOF. A later record is a protocol
failure. Process exit code, normal versus forced close, EOF observation, and
protocol classification remain independent evidence. A completed turn
followed by exit 17 is not completion.

## Preventive host-control boundary

The control request uses a synthetic capability overlay with empty MCP
servers, zero project-document discovery, and disabled web search, apps,
memories, plugins, shell snapshots, and skills. It exposes no workspace,
environment root, shell, Docker socket, or native file-edit root. Runtime
protocol refusal remains defense in depth; it is not the preventive boundary.

`HostControlBwrapPolicy` content-attests an absolute bwrap and Codex path and
rejects symlinked components, `..` aliases, changed source objects, overlapping
sources, and sources overlapping forbidden roots. Immediately before launch it
opens the attested inodes and uses bwrap `--ro-bind-fd`; bwrap itself is
executed through its attested descriptor. The descriptor argv contains no host
source path, and the temporary launcher descriptor mount is hidden before the
control executable starts. The launcher uses:

- an exact bwrap executable, never ambient `PATH`;
- an explicit minimal environment and controlled cwd;
- `close_fds=True`, a new session, and no shell;
- private namespaces, `/proc`, minimal `/dev`, tmpfs `/tmp`, and an otherwise
  empty mount view;
- a read-only Codex executable at `/runtime/codex`;
- read-only Codex home, runtime, control, and `/etc` parents;
- only individually authorized configuration, certificate, resolver, hosts,
  and authentication files.

The production path does not inherit loader, Python, shell, proxy, Git,
provider, or unrelated credential variables. Synthetic tests use an isolated
network namespace. Production service-only egress and exclusive
authentication access remain blocked on the OS-enforced
`AuthenticationBoundary`; this backend does not claim either prematurely.

## Journal and external anchor

Before the first mutable session record, the store creates and fsyncs an
external trusted session-authority anchor. The anchor binds the complete
backend authority, controller authority, and workspace identity. It is outside
the mutable session-log tree.

One external per-session lock transaction covers state reconstruction,
sequence allocation checks, full-chain and external-tail verification,
append, journal fsync, required directory fsync, and atomic durable-tail
publication. The external tail binds the trusted anchor, exact event index,
event fingerprint, and byte length. Replacing a journal with a newly computed
chain cannot replace its anchor or durable tail.

The ordered evidence includes control/capsule processes, protocol binding,
tool request, effect execution, tool result, control terminal truth, cleanup,
frozen `ProviderOutput`, session terminal, and downstream handoff. Concrete
sessions cannot record a result before effect execution, cleanup before
control terminal truth, `ProviderOutput` before cleanup, or terminal state
before both cleanup and `ProviderOutput`. No effect is accepted after terminal
state. A crash leaving a durable unpaired request is evidence of an
indeterminate effect and is never replay authorization.

## Exact capsule request and file boundary

Every request carries and matches backend session, controller session, capsule
handle, monotonic sequence, RPC and call identities, and mission-authority
fingerprint.

File operations and canonical intake share a closed portable path grammar.
It rejects absolute and traversal paths, backslashes, empty/dot components,
`.git`, trailing dots or spaces, Windows-reserved names, colons/ADS shapes,
control characters, non-NFC names, case-fold collisions, and Unicode
normalization collisions. Live workspace audits reject symlinks, hardlinks,
special files, mount crossings, and bound violations before and after each
effect. The controller also attests the exact idle capsule process tree before
and after every effect. A background or daemonized descendant causes the
controller to quarantine the entire process tree and refuse the result. The
process tree is killed after the evidence freeze, so no untrusted process can race the
validate/open sequence of a later file operation. Execution uses fixed
controller scripts and no host shell.
Create/replace/upsert semantics are exact and independently enforced before
canonical intake.

## Docker boundary

Docker is an absolute content-attested executable with a closed environment
and controlled cwd. The image tag is inspected only to establish an immutable
content ID; `docker run` and snapshot extraction use that ID directly.
Resource strings are accepted only in canonical numeric forms and also stored
as canonical integers.

Run-bound unpredictable container, volume, workspace, and capsule-handle names
carry exact session/controller/handle/mission labels. Objects are independently
inspected after launch. Removal requires every exact authority label; an
unlabeled or differently labeled collision is not removed. Inspect or daemon
communication failure is unknown/failure, never absence.

The capsule runs with:

```text
--init
--user <non-root uid>:<non-root gid>
--read-only
--cap-drop ALL
--security-opt no-new-privileges:true
--network none
--pids-limit <canonical integer>
--cpus <canonical decimal>
--memory/--memory-swap <canonical size>
--ulimit nofile=<bound>:<bound>
--tmpfs /tmp:rw,noexec,nosuid,nodev,<bound>
--mount type=volume,...,volume-opt=type=tmpfs,volume-opt=device=tmpfs,
        volume-opt=o=size=<hard workspace byte ceiling>
```

No credential, host workspace, source repository, Docker socket, host network,
or Git authority is mounted. Standard output and error are captured
incrementally with hard byte bounds. Timeout or overflow kills the Docker CLI
process group and the complete container process tree. Cleanup attests exact
ownership and proves container and quota-volume removal.

## Frozen output and exact truth

The controller pauses the complete running capsule process tree, or
independently attests that a crashed container is already stopped, then copies
the still-mounted hard-quota volume through a separately secured extractor.
It refuses symlinks, hardlinks, special files, ambiguous paths, mount
crossings, mutation during observation, or bounds violations.

Atomic publication creates a content-addressed directory and manifest with
every relative path, type, mode, size, and byte hash. The snapshot is bound to
the cleanup fingerprint and cleanup journal tail. Every later reader
re-observes all bytes and metadata and refuses mutation; an earlier
observation is not timeless authority.

`ExecutionTruth` inside `ProviderOutput` independently records app-server exit
code, normal/forced close, protocol terminal class, capsule result, controller
classification, cleanup, journal tail, frozen snapshot, and frozen-binding
identities. Reconstruction and return require mutually matching cleanup,
terminal journal, and output evidence. `ProviderOutput` contains no Git
authority and its completion text remains an untrusted claim.

## Packaging and compatibility

The wheel and sdist include this document and the exact generated protocol
schema subset and manifest. Build-system dependencies are exact pins, so an
isolated build does not rely on an ambient `wheel` installation. Isolated
imports require no home, spike, historical-run, or Windows-path artifact.

The generic material-continuity contracts remain unchanged: one canonical
accepted-material identity binds intake, checkpoint, behavior, durability,
and finalization; source mutation refuses; the finalizer builds the exact
accepted tree from an empty Git index under isolated Git configuration and
hooks; intake publication states are truthful; and replay validation is
evidence-only.

Historical ACP/Cursor code and detached audit worktrees are not authorities for
this backend and are not modified by its operation.
