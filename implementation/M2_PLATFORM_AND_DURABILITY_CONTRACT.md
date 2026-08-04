# Admissible Paired Runner — Milestone 2
## Platform and Durability Contract

Status: `M2_PLATFORM_CONTRACT_SELECTED`

Milestone 0 deliberately recorded that no physical host had been selected.
Milestone 2 is the first platform-dependent runtime milestone, so this document
selects the initial qualification platform **before** any runtime code is
trusted, and it states exactly what the selected platform does and does not
guarantee. It is governed by ADR-015 in `ADR_REGISTER.md`.

Nothing in this contract claims a clean-host qualification, an installed-path
qualification, a provider path, or a production authority path.

---

## 1. Supported M2 host semantics

| Input | Selected M2 contract |
|---|---|
| Operating-system semantics | Linux POSIX process, signal, and filesystem semantics |
| Interpreter | CPython, standard library only |
| Interpreter validated during M2 | CPython 3.12.3, `/usr/bin/python3.12` |
| Development/qualification host used | Linux 6.18.33.2-microsoft-standard-WSL2, `linux-x86_64` |
| Required non-standard packages | none |
| Node.js dependency | none |
| Provider dependency | none |
| Production authority dependency | none |
| Windows / Cursor product path | explicitly out of contract |

The four standard-library facilities the substrate depends on are `os`
(descriptor-relative filesystem calls), `selectors`, `subprocess`, and
`signal`. `resource` is used only for best-effort measurements and its absence
degrades to an explicit availability value rather than to a fabricated zero.

**WSL2 success is not clean-host Linux qualification.** Every measurement in
`M2_OUTPUT_SOAK_REPORT.json` and `M2_VALIDATION_REPORT.json` was taken under
WSL2. WSL2 is a Linux kernel, so the POSIX semantics below are real, but the
storage stack beneath it is virtualised, so its `fsync` behaviour is not
evidence about a bare-metal or cloud Linux host. Clean-host qualification
remains open work for Milestone 8.

## 2. Process-group and session semantics

* Every supervised command is started with `start_new_session=True`, so the
  direct child becomes both a session leader and a process-group leader, and the
  process-group id equals the child pid.
* Descendants are addressed as a group with `killpg`. A descendant that
  deliberately leaves the group with its own `setsid` is outside what this
  contract can reach; that limitation is stated rather than hidden.
* Termination escalation is ordered and documented:
  1. `SIGTERM` to the process group;
  2. a `2000 ms` grace period during which both pipes keep draining;
  3. `SIGKILL` to the process group.
* The direct child is always reaped. Group emptiness is confirmed
  best-effort with `killpg(pgid, 0)` and recorded as `descendants_reaped`.
* The controller never uses a shell. `argv` is an explicit array; a bare command
  string is refused by the Milestone 1 request type before it reaches here.

## 3. Filesystem and symlink assumptions

* The physical workspace root must be an absolute path, must not itself be a
  symlink, and must equal its own `realpath`.
* Every path component is opened relative to a directory descriptor anchored at
  the root, using `O_NOFOLLOW` (and `O_DIRECTORY` for intermediate components).
  There is no "validate the string, then open the path" window.
* `list_files` lists a symlink as an entry but never traverses it.
* `read_file` refuses a final symlink (`ELOOP`) and refuses any symlinked parent
  component.
* `write_file` refuses a pre-existing final symlink, and its commit step is
  `rename()`, which replaces the destination name itself and can never write
  *through* a symlink. The refusal is therefore a policy, not the safety
  mechanism.
* `run_command.cwd` is proven symlink-free component by component and is then
  re-checked with `realpath` before the child is started.

**Documented unavoidable limitation.** `subprocess.Popen` accepts a `cwd` path
string, not a directory descriptor. The substrate proves the path is
symlink-free with descriptor-relative opens and then re-verifies it with
`realpath`, but a sufficiently privileged concurrent mutation of the workspace
between that verification and `execve` is not excluded by the standard library
alone. This is recorded as a bounded limitation of the CPython interface, not as
a solved problem.

## 4. Atomic publication guarantees

One primitive publishes every immutable object:

1. serialize through the Milestone 1 canonical representation;
2. create a temporary file **in the target directory** with
   `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`;
3. write all bytes, then `fsync` the file descriptor;
4. commit with `os.link()`, which is atomic and, unlike `rename()`, **never
   replaces** an existing name — a different object can never be overwritten;
5. `fsync` the parent directory;
6. unlink the temporary name;
7. read the committed bytes back and compare them with what was serialized.

Publication states are exactly:

| State | Meaning |
|---|---|
| `ABSENT` | no committed object exists for this identity |
| `RESERVED` | an identity is claimed but not yet committed |
| `PUBLISHED` | canonical bytes are committed and were read back |
| `DUPLICATE_IDENTICAL` | the identity exists and its bytes are byte-identical |
| `CONFLICT_DIFFERENT` | the identity exists with different bytes; fails closed |
| `CORRUPT` | committed bytes are not canonical; fails closed |
| `AMBIGUOUS` | the identity cannot be classified from bytes alone |

**Idempotency rule.** An immutable identity may be published once.
Re-publishing byte-identical canonical content is `DUPLICATE_IDENTICAL` and
succeeds without rewriting anything. Any other content for the same identity is
`CONFLICT_DIFFERENT` and raises. Temporary files carry a reserved
`.tmp-publication-` prefix and are never counted as committed objects.

## 5. fsync guarantees and limitations

The contract claims exactly this and no more: after `publish` returns
`PUBLISHED`, the file contents and the parent directory entry have both been
handed to `fsync`, and the committed bytes have been read back and compared.

It does **not** claim:

* that the storage device honoured the flush (write caches, virtualised block
  devices, and `nobarrier` mounts can all defeat `fsync`);
* anything about WSL2's 9p/virtio-backed filesystems specifically;
* anything about network filesystems, overlay filesystems, or container layers;
* power-loss durability, which was not physically tested in Milestone 2.

Simulated crashes are deterministic fault injections at named points, not power
cuts. That is stated plainly in `M2_CRASH_MATRIX.json`.

## 6. Cancellation semantics

Cancellation is cooperative at the controller and forcible at the child. A
`CancellationToken` is polled by the same loop that drains the pipes, so a
cancellation cannot be blocked by a full pipe. On cancellation the substrate
applies the escalation of section 2, reaps the child, records
`cancelled = true`, and produces a `CANCELLED` receipt. A `CANCELLED` receipt
never claims completion and never carries a successful typed result.

## 7. Timeout semantics

The timeout is the request's `timeout_ms`, measured from just before `Popen` on
the monotonic clock. It is enforced by the same drain loop, so a timeout cannot
deadlock on a full pipe. A timeout produces a `TIMED_OUT` receipt, which the
Milestone 1 matrix already marks as `reconciliation_required` and never as
completed. The Milestone 1 request schema caps `timeout_ms` at 60 000 ms; a
longer single command is outside the current tool grammar.

## 8. Resource-observation semantics

| Metric | Source | Availability recorded |
|---|---|---|
| child CPU user/system time | `getrusage(RUSAGE_CHILDREN)` delta | `OBSERVED_BEST_EFFORT` |
| child peak RSS | `getrusage(RUSAGE_CHILDREN).ru_maxrss` | `OBSERVED_BEST_EFFORT` |
| controller peak retained output | exact high-water mark of the retention buffers | `OBSERVED` |
| wall clock | `time.time()` in integer milliseconds | `OBSERVED` |
| monotonic time | `time.monotonic_ns()` | `OBSERVED` |

`RUSAGE_CHILDREN` aggregates every reaped child of the controller, so CPU and
RSS are an *upper bound attributable to this effect*, not an isolated
per-process measurement. That is why they are `OBSERVED_BEST_EFFORT` and why the
semantics string is persisted with every record.

A metric that is unavailable is recorded as `None` with an explicit
availability value. **A missing measurement is never recorded as zero.** No
token, cost, or model metric exists in Milestone 2.

## 9. Output-retention semantics

* Retention per stream is exactly the request's `max_output_bytes`.
* The full byte count and a domain-separated SHA-256 of the *entire* stream are
  always recorded, independently of retention.
* Truncation is explicit in both the typed result and the stream observation.
* A bounded cut can split one multi-byte UTF-8 sequence. At most three trailing
  bytes may be trimmed, and that repair is reported distinctly as
  `UTF8_DECODED_AFTER_BOUNDARY_TRIM`.
* Output that is not valid UTF-8 for any other reason is **byte-observed and
  text-refused**: the byte count and stream hash are kept, the retained text is
  empty, the stream status is `REFUSED_NON_UTF8`, and the tool result is
  `FAILED` with `non_utf8_output`. Nothing is silently replaced.
* File content that is not valid UTF-8 is refused outright (`non_utf8_file`).

### Controller-memory acceptance threshold

Declared **before** the heavy soak was run:

* controller retention is bounded analytically by
  `2 * max_output_bytes + 262144` bytes (two retention buffers plus four 64 KiB
  read blocks of fixed overhead);
* measured controller RSS growth above the pre-soak baseline must not exceed
  **64 MiB** for the governing 1 GiB / 1 000 000-line workload.

There is no queue anywhere in the new path, so controller memory is a function
of the caps and the read block size, never of total output volume.

## 10. Temporary-root requirements

* Every physical effect in the Milestone 2 test suite happens inside a
  disposable directory created with `tempfile.mkdtemp` by the test process and
  removed afterwards.
* No test writes to the repository worktree, and no test writes to `/opt`,
  `/etc`, `/var/lib`, or `/run`.
* The durable object store root and the workspace root are separate directories
  inside that disposable root, so a workspace effect can never overwrite
  evidence.
* Supervised commands receive an explicit environment
  (`PATH`, `LANG`, `LC_ALL`, `TZ`, `HOME`, `PWD`) and inherit nothing else, so
  no credential or provider variable can reach a child.

## 11. Unsupported platforms

The following are explicitly **not** covered by this contract and must not be
claimed on the basis of Milestone 2 evidence:

* Windows, including the Windows Cursor `--force --trust` product path;
* macOS;
* any host without POSIX sessions, process groups, or `O_NOFOLLOW`;
* any host requiring Node.js or npm;
* network, overlay, or container-layer filesystems;
* clean-host installed-path execution;
* production authority roots and the production owner broker.

## 12. What remains for clean-host qualification

1. Run the full functional, crash, and heavy-soak matrices on a bare-metal or
   cloud Linux host with a known storage stack.
2. Qualify `fsync` behaviour against that storage stack, including a real
   power-loss or device-level fault model if durability is to be claimed more
   strongly than section 5 allows.
3. Qualify the exact installed entry points rather than a source checkout
   (`OPS-07`, Milestone 8).
4. Repeat the resource-observation measurements where `RUSAGE_CHILDREN`
   aggregation can be isolated, or replace them with a per-process source.
5. Establish the behaviour of a descendant that escapes the process group with
   its own `setsid`.
6. Re-measure the controller-memory threshold on the qualification host before
   treating 64 MiB as a portable bound.

---

## Milestone 2 critical repairs — platform additions

The platform contract gains three hard requirements. Each is checked before any
effect is possible, and each refuses rather than degrading.

### Capsule mechanism

`bubblewrap` (`bwrap`) must be present **and** unprivileged user namespaces must
actually work. `probe_capsule_readiness()` constructs a real throwaway capsule
and requires the kernel to demonstrate: `/home` absent, `/etc/passwd` absent, a
private `/proc`, a private and empty `/tmp` on a different device than `/usr`,
and an outbound connect failing with `ENETUNREACH`. A present binary on a host
with user namespaces disabled is therefore not mistaken for a working boundary.

If the probe fails, `SandboxUnavailable` is raised during readiness — before any
proposal is published. There is no unsandboxed fallback path in the code.

Full contract: `implementation/M2_SANDBOX_CONTRACT.md`.

### Evidence-root isolation

Before proposal publication the workspace and the durable store must be proven
physically disjoint: both absolute, non-symlink, canonical directories opened as
descriptors; neither an ancestor of the other; distinct `(device, inode)`
identities so a hard link, bind alias, or rename cannot make two names refer to
one directory; and a store root that is not group- or world-accessible. The
identities are recorded and rechecked at preflight, so a root replaced after
binding is detected rather than silently acted upon.

### Filesystem observation cost

A complete observation now streams the bytes of every regular file, so its cost
is proportional to workspace size rather than entry count. The entry limit
(`MAX_OBSERVED_TREE_ENTRIES`) and the byte limit (`MAX_OBSERVED_CONTENT_BYTES`,
2 GiB) both produce an explicit incomplete state that cannot serve as a final
repository fingerprint. An observation carrying any error, or any truncation,
can never be `COMPLETE`.

### Preserved bounded-stream guarantees

The bounded-stream implementation is unchanged by these repairs. The heavy soak
was re-run through the sandboxed command path and produced byte-identical stream
fingerprints with controller retention inside the declared bound, so the scoped
heavy-output evidence for LONG-07 and LONG-08 is preserved.


## Addendum — Milestone 2 second critical repairs

### The one replaceable durable object

Every object in the durable store is immutable and published with no-replace
semantics, with exactly one exception: `run-index-anchor.<run_id>.json`, the run
index's committed head. It is written by temporary file → `fsync` → atomic
`rename` → directory `fsync`, so a reader observes the previous committed head or
the new one and never a partial document.

The exception is necessary rather than convenient. Without a single name that
always states how far a run got, deleting the newest event together with its head
record leaves a shorter chain that is internally consistent and therefore
undetectable. The anchor moves only forward, and only after the event it commits
is already durable; the window between those two steps is the named
`HEAD_UPDATE_PENDING` crash state.

### Durability of the head update

The anchor's `rename` is atomic with respect to the directory entry. The
guarantee this contract makes is the same one it makes for `os.link`: after the
directory `fsync` returns, the name resolves to the new bytes on a conforming
Linux filesystem. No claim is made beyond what `fsync` on the selected platform
provides, and this is not a power-loss or device-level fault model.

### Crash classification

Six fault points were added, covering every boundary of the run-index event and
committed-head publication. Their declared durable consequences, including the
resulting index state, are in `implementation/M2_CRASH_MATRIX.json`; the
classification rules are in `implementation/M2_DURABLE_EVENT_INDEX_SPEC.md`.

### Rollback

Deleting the newest event *and* rewinding the committed head to a still-valid
earlier head is undetectable by any purely local record. This contract does not
claim otherwise. `DurableRunIndex.head_anchor()` returns exactly the value an
external anti-rollback anchor would pin; Milestone 2 implements no such anchor,
and any future multi-session design must supply one.

### Resource containment on the qualification host

`Linux 6.18.33.2-microsoft-standard-WSL2` delegates no writable cgroup v2 subtree
to the running user, so the containment mechanism in force is `RLIMIT` and
aggregate process-domain accounting is unavailable. This is recorded in every
resource observation rather than assumed away. WSL2 remains explicitly not a
clean-host qualification.
