# Codex ChatGPT authentication and service boundary (V0)

## Scope and status

This is the provider-free V0 boundary for the host Codex 0.145.0 app-server
and Docker capsule backend. It does not prove that a real ChatGPT login can
refresh, that the destination set is complete, or that a provider turn
succeeds. Those are deferred to a separately authorized real canary. The
implementation and tests use synthetic authentication and local synthetic TLS
only.

The integrated architecture result is
`CHATGPT_CODEX_OS_ENFORCED_BOUNDARY_FEASIBLE`.

## Process and namespace topology

The trusted boundary launcher creates every channel before it starts the
general controller:

```text
host network namespace
  boundary launcher (TCB; journal anchor owner)
    authentication broker (TCB; auth-source FD, private ephemeral home)
      writable ephemeral CODEX_HOME directory FD
          |
          v
    Codex namespace bootstrap (TCB)
      private mount + PID + network namespaces
      loopback only, no resolver, no workspace, no Docker
      pinned Codex 0.145.0 app-server (TCB)
          | inherited app-server socketpair
          v
    general controller (TCB)
      empty mount namespace + private network namespace + Landlock defense
      app-server FD + capsule-broker FD only
          |
          v
    capsule broker (TCB, root-equivalent)
      exec-clean private mount/PID/network/user namespaces
      exact Docker executable/socket FDs; no auth input or auth protocol
      exact image ID, mount graph, labels, limits and operations only
          |
          v
      network-none, non-root, capability-free disposable capsule

    egress relay (TCB; host network namespace)
      accepts the listener created in Codex netns through SCM_RIGHTS
      CONNECT:443 -> sealed hostname/IP authority only; TLS remains end-to-end
```

Canonical intake, independent verification, and the Git-isolated finalizer
remain downstream and independent. No broker receives staging, commit, push,
or publication authority.

## Unavoidable V0 trusted computing base

V0 trusts:

1. the boundary launcher and namespace bootstrap;
2. the authentication broker;
3. the exact Codex 0.145.0 process;
4. the general controller;
5. the preventive egress relay;
6. the capsule broker and its closed Docker controller implementation;
7. canonical intake, independent verification, and the finalizer.

The capsule broker is explicitly root-equivalent on this rootful Docker host.
Possession of the Docker socket is host-root authority. It is isolated from
the controller and Codex, kept small, and accepts no caller bind path, image,
Docker fragment, privileged flag, host namespace, device, capability,
inherited environment, or socket mount. This is not a claim of rootless
Docker and the integration performs no privileged host installation.

## Canonical authority

`OSBoundaryAuthority` fingerprints the complete launch:

- boundary launcher, authentication broker, capsule broker and egress relay
  identities;
- every broker wire-schema identity;
- exact inherited FD/socket topology;
- controller, Codex and capsule-broker confinement policies;
- network namespace and relay policy;
- the version-specific destination-manifest identity;
- authentication metadata (never content) policy;
- writable ephemeral `CODEX_HOME` policy;
- cleanup order;
- all runtime executable, image and protocol dependencies.

`BackendExecutionAuthority` V3 embeds this authority and both authority and
launch fingerprints. Production construction requires an explicit authority.
A caller-provided `OS_ENFORCED` string is not an attestation.

The launcher opens content-attested executables before confinement and uses
descriptor-backed bubblewrap binds. Codex bubblewrap options are carried in a
sealed memfd through `bwrap --args`; the fixed namespace-bootstrap command is
the only ordinary sandbox argv and no authentication source path appears
there. The controller is started inside an empty mount
view, with a closed environment, cwd and inherited descriptor set. It cannot
see the source repository, authentication source, ephemeral Codex home,
Docker executable/socket, host home, user-manager sockets, path sockets, or
the host abstract-socket namespace.

Landlock is an empty allowlist applied after startup when the kernel supports
it. It is defense in depth. The empty mount namespace and private network
namespace are the primary pathname and socket boundaries.

## Authentication broker

The authentication broker protocol has only `PREPARE`, `HANDOFF`, `CLEANUP`
and `SHUTDOWN`. The source is an inherited regular-file FD. The wire protocol
cannot name a source path and never transports authentication bytes.

The broker:

- validates only allowed stat metadata (regular file, single link, bounded
  size);
- copies bytes into a `0600` auth file under a broker-owned `0700` ephemeral
  home;
- closes the real source FD immediately;
- hands the launcher a directory FD for bubblewrap `--bind-fd`;
- leaves the real source outside the Codex namespace;
- overwrites, fsyncs, unlinks and removes every ephemeral-home file at
  cleanup.

Evidence contains broker identity, allowed source metadata, ephemeral-home
device/inode identity, handoff and cleanup. It forbids source path, content,
content hash, token, cookie and authorization values.

Login refresh is not provider-free proof. The real canary must observe whether
Codex can refresh within the writable ephemeral home and whether cleanup still
holds.

## Preventive egress relay

Codex has a private network namespace with loopback only and no resolver. Its
namespace bootstrap creates the loopback TCP listener and transfers that
listener FD to the host relay with `SCM_RIGHTS`. Codex has no general route.

The relay accepts canonical `CONNECT host:443 HTTP/1.1` only. It resolves each
authorized name once outside the Codex namespace before the session, validates
public addresses, seals exact IPs and subsequently connects to stored IP
literals. It never resolves during CONNECT. A new CONNECT (including one
caused by an application redirect) must already exist in the sealed manifest.

The relay rejects non-443, unauthorized, private, loopback, link-local, Unix
and ambiguous destinations. It enforces connection, concurrency, byte and
duration budgets. It tunnels TLS without termination. Durable evidence
contains hostname, pinned IP, byte counts and terminal classification—never
CONNECT headers, TLS plaintext or bodies.

The Codex 0.145.0 ChatGPT manifest currently records:

| Destination | Provider-free evidence |
| --- | --- |
| `chatgpt.com:443` | observed required |
| `ab.chatgpt.com:443` | observed startup behavior |
| `auth.openai.com:443` | statically discovered; not exercised |

These observations are version-specific, not permanent truth. Neither Codex
nor the controller can widen the manifest. A real canary must stop at the
first unsealed request; it must not learn and add destinations during a run.

## Capsule broker protocol

The broker uses an inherited `AF_UNIX/SOCK_SEQPACKET` socketpair. There is no
filesystem socket to replace. Packets are bounded canonical JSON, reject
duplicate keys, reject truncation/ancillary ambiguity, and bind the backend,
controller and capsule sessions, broker/mission authorities, monotonically
increasing sequence, and exact durable dynamic-tool request fingerprint.

The fixed operations are `CREATE_SESSION`, `RECOVER_CLEANUP`, `EXECUTE_TOOL`,
`FREEZE_WORKSPACE`, `OBSERVE_FROZEN`, `BIND_FROZEN`,
`TERMINATE_CLEANUP`, `GET_FROZEN_REFERENCE` and `SHUTDOWN`. Tool execution
still accepts only the strict `capsule_effects` dynamicTools grammar.

Only the broker constructs Docker argv. It uses the content-attested Docker
executable, exact image ID, broker-owned roots, unpredictable names, exact
labels, fixed volume graph and fixed security/resource options. Before
removal it proves exact ownership. Docker communication failure is `UNKNOWN`,
never evidence of absence. Normal startup and forced-exit recovery both use
the same exec-clean, empty-root broker namespace; recovery has no unconfined
Docker-owning fallback.

## Durable lifecycle and failure truth

The boundary lifecycle fixes this order: authority acceptance; executable and
broker attestation; external journal anchor; ephemeral home; Codex namespaces
and listener; sealed pins; capsule broker; confined controller; Codex
app-server; paired dynamic tools/results; Codex terminal; frozen/terminated
capsule; broker cleanup; durable `ProviderOutput`; canonical-intake handoff.

`ExecutionTruth` V2 binds the OS authority, capsule-broker terminal,
all-boundary terminal, cleanup, external journal tail, frozen workspace and
frozen binding. The journal writes boundary-terminal evidence after cleanup
and immediately before `ProviderOutput`. Production completion fails closed
if any authentication, Codex, egress, capsule-broker, process-tree, namespace,
socket or journal terminal is missing.

## Provider-free evidence versus real-canary evidence

Provider-free tests prove with temporary synthetic material that the
controller cannot stat/open auth or ephemeral home and has neither Docker path
nor socket; the broker refuses the rootful-Docker bind-mount escalation; the
capsule has no auth source or Docker socket; sealed local TLS succeeds while
wrong-CA and unauthorized CONNECT fail; resolution occurs once; relay evidence
has no plaintext; and all Docker objects, sockets, namespaces, process trees
and ephemeral home are cleaned.

A separately authorized real canary must still observe login/refresh, the
complete destination set, TLS/service compatibility, provider response, and
cleanup under real timing. It must use the already sealed authority and stop
on an unsealed destination. Those observations must never be backfilled into
provider-free evidence.
