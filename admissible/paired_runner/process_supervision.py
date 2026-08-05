"""Bounded local process supervision for the shared effect substrate.

The readiness audit (AUD-MJ06) found that the historical one-shot path pushed
every output line into an unbounded ``queue.Queue`` while a bounded text cap
gave the appearance of safety.  This module does not reuse that architecture
and contains no queue at all.

Instead, a single controller thread multiplexes the child's ``stdout`` and
``stderr`` pipes with :mod:`selectors`.  Each stream keeps:

* a retention buffer capped at the request's ``max_output_bytes``;
* a running total byte counter for the full stream;
* an incremental SHA-256 of every byte the child produced.

Controller memory is therefore a function of the two retention caps and the
read block size, not of the total output volume.  There is no per-line object,
no list of lines, and no unbounded structure of any kind.

The module never interprets policy, never decides acceptance, and never
consults a provider.  It only starts, supervises, bounds, terminates, reaps,
and observes one local process.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
import selectors
import subprocess
import threading
import time
from typing import Any, Callable

from .canonical import Fingerprint
from .observation import (
    ProcessObservation,
    ResourceObservation,
    StreamObservation,
)
from .capsule_seccomp import open_program_descriptor
from .cgroup_launch import (
    GateReleaseOutcome,
    RELEASE_NOT_RELEASED,
    RELEASE_OUTCOME_UNKNOWN,
    RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
    attach_and_verify_real,
    monotonic_release_truth,
)
from .process_ownership import (
    ABORT_TOTAL_DEADLINE_MS,
    CHILD_SUBREAPER,
    REAPER_NONE,
    Deadline,
    ProcessOwnershipEvidence,
)
from .resource_limits import (
    MECHANISM_CGROUP_AND_RLIMIT,
    MECHANISM_NONE,
    CgroupDelegation,
    EffectCgroup,
    ResourceBounds,
    ResourceContainmentUnavailable,
    containment_semantics,
    delegation_from_topology_failure,
    effective_mechanism,
    initialize_cgroup_topology,
    probe_cgroup_delegation,
)
from .runtime_binding import BoundRuntime
from .sandbox import (
    CAPSULE_TEARDOWN_TIMEOUT_SECONDS,
    MAX_STATUS_BYTES,
    CapsuleSpecification,
    capsule_argv,
    parse_capsule_status,
)


try:  # pragma: no cover - resource is POSIX-only; the platform contract is POSIX
    import resource as _resource
except ImportError:  # pragma: no cover
    _resource = None


READ_BLOCK_BYTES = 65_536
#: Documented bounded controller overhead beyond the two retention caps.
CONTROLLER_FIXED_OVERHEAD_BYTES = 4 * READ_BLOCK_BYTES
STREAM_FINGERPRINT_DOMAINS = {
    "stdout": "admissible.paired_runner.m2.stream.stdout",
    "stderr": "admissible.paired_runner.m2.stream.stderr",
}
#: Ordered, documented escalation applied to the whole private PID namespace.
#: The namespace, not the process group, is the boundary, so a descendant cannot
#: evade this by calling ``setsid`` or by double-forking.
TERMINATION_ESCALATION_ORDER = ("SIGTERM_PID_NAMESPACE", "SIGKILL_PID_NAMESPACE")
GRACE_PERIOD_MS = 2_000
MAX_UTF8_TRIM_BYTES = 3

RESOURCE_MEASUREMENT_SEMANTICS = (
    "Child CPU time and peak RSS are read from getrusage(RUSAGE_CHILDREN) deltas taken "
    "around this exact supervision call.  RUSAGE_CHILDREN aggregates every reaped child of "
    "this controller, so the values are an upper bound attributable to this effect rather "
    "than an isolated per-process measurement; they are recorded as OBSERVED_BEST_EFFORT. "
    "controller_peak_retained_output_bytes is the exact high-water mark of bytes this "
    "controller held in its retention buffers and is OBSERVED."
)


class CancellationToken:
    """A cooperative cancellation signal owned by the caller."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class _BoundedStream:
    """Bounded retention plus full-volume accounting for one pipe."""

    def __init__(self, name: str, retention_cap: int) -> None:
        self.name = name
        self._cap = retention_cap
        self._retained = bytearray()
        self.total_bytes = 0
        self._digest = hashlib.sha256()

    def feed(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        self._digest.update(chunk)
        remaining = self._cap - len(self._retained)
        if remaining > 0:
            self._retained += chunk[:remaining]

    @property
    def retained_bytes(self) -> int:
        return len(self._retained)

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self._retained)

    def decode(self) -> tuple[str, str]:
        """Return ``(text, decode_status)`` and never guess at broken bytes."""

        raw = bytes(self._retained)
        try:
            return raw.decode("utf-8", "strict"), "UTF8_DECODED"
        except UnicodeDecodeError:
            pass
        if self.truncated:
            # A bounded cut can split one multi-byte sequence.  Trimming at most
            # three trailing bytes is the only repair permitted, and it is
            # reported distinctly from a clean decode.
            for trim in range(1, MAX_UTF8_TRIM_BYTES + 1):
                if trim > len(raw):
                    break
                try:
                    return raw[:-trim].decode("utf-8", "strict"), "UTF8_DECODED_AFTER_BOUNDARY_TRIM"
                except UnicodeDecodeError:
                    continue
        # Fail closed: the bytes are still fully counted and fingerprinted, but
        # no lossy text is presented as if the child had produced it.
        return "", "REFUSED_NON_UTF8"

    def observation(self) -> tuple[StreamObservation, str, str]:
        text, status = self.decode()
        if status == "REFUSED_NON_UTF8":
            retained = 0
            truncated = self.total_bytes > 0
        else:
            retained = len(text.encode("utf-8"))
            truncated = self.total_bytes > retained
        observation = StreamObservation.create(
            stream_name=self.name,
            total_bytes=self.total_bytes,
            retained_bytes=retained,
            retained_truncated=truncated,
            stream_fingerprint=Fingerprint(
                "sha256", STREAM_FINGERPRINT_DOMAINS[self.name], self._digest.hexdigest()
            ).validated(),
            text_decode_status=status,
        )
        return observation, text, status


@dataclass(frozen=True)
class SupervisedProcessResult:
    """The complete typed observation of one supervised local process."""

    process_observation: ProcessObservation
    stdout_observation: StreamObservation
    stderr_observation: StreamObservation
    resource_observation: ResourceObservation
    stdout_text: str
    stderr_text: str
    stdout_decode_status: str
    stderr_decode_status: str

    @property
    def refused_non_utf8(self) -> bool:
        return "REFUSED_NON_UTF8" in {self.stdout_decode_status, self.stderr_decode_status}


def _now() -> tuple[int, int]:
    return int(time.time() * 1000), time.monotonic_ns()


def _rusage_children() -> Any:
    if _resource is None:  # pragma: no cover
        return None
    return _resource.getrusage(_resource.RUSAGE_CHILDREN)


_DELEGATION_LOCK = threading.Lock()
_DELEGATION_CACHE: CgroupDelegation | None = None
_DELEGATION_PID: int | None = None


def cgroup_delegation(*, force: bool = False) -> CgroupDelegation:
    """Probe cgroup v2 delegation once per controller process and reuse the answer.

    The answer describes a topology owned by one PID: the trusted manager leaf
    holds *this* process, and the delegated parent distributes controllers only
    because this process left it.  A cache inherited across ``fork`` therefore
    describes somebody else's topology and is never reused; the child re-derives
    it, which either reuses the existing manager leaf it is already a member of
    or fails closed.
    """

    global _DELEGATION_CACHE, _DELEGATION_PID
    with _DELEGATION_LOCK:
        if _DELEGATION_CACHE is None or force or _DELEGATION_PID != os.getpid():
            _DELEGATION_CACHE = probe_cgroup_delegation(force=force)
            _DELEGATION_PID = os.getpid()
            return _DELEGATION_CACHE
        cached = _DELEGATION_CACHE
        if not cached.available:
            return cached
        # M2-B29.  The cached object is a promise about kernel state, so it is
        # never handed back on the strength of having been computed once.  Every
        # production effect re-derives the topology from the kernel first; a
        # contradiction fails closed and is *not* silently re-bootstrapped.
        topology = initialize_cgroup_topology()
        if not topology.initialized:
            _DELEGATION_CACHE = delegation_from_topology_failure(topology)
            return _DELEGATION_CACHE
        return cached


#: How long the abort path waits for the effect cgroup to become quiescent.
ABORT_QUIESCENCE_TIMEOUT_SECONDS = 5.0


def _close_owned_descriptors(descriptors: tuple[int, ...]) -> dict[str, Any]:
    """Close exactly the descriptors this controller owns, once each."""

    closed: list[int] = []
    already: list[int] = []
    for descriptor in descriptors:
        if descriptor is None or descriptor < 0:
            continue
        try:
            os.close(descriptor)
            closed.append(descriptor)
        except OSError:
            # EBADF means this descriptor was already closed; that is the
            # idempotent case, not a leak and not a second close of a
            # descriptor some other part of the process now owns.
            already.append(descriptor)
    return {"closed": sorted(closed), "already_closed": sorted(already)}


def _legacy_terminate_and_reap(process: Any, ownership: ProcessOwnershipEvidence) -> bool:
    """Bounded kill/wait/poll for a launcher object with no ownership interface.

    Test stand-ins and any future launcher implementation that does not carry
    the trusted-ownership interface are still cleaned up, but the reaper is
    recorded as unidentified rather than attributed to this controller.
    """

    killed = False
    try:
        process.kill()
        killed = True
    except Exception:
        # Already gone, or the helper no longer answers.  Reaping below still
        # decides whether anything of ours is alive.
        killed = False
    try:
        ownership.launcher_exit_code = process.wait(timeout=CAPSULE_TEARDOWN_TIMEOUT_SECONDS)
        ownership.launcher_reaped = True
    except Exception:
        try:
            ownership.launcher_exit_code = process.poll()
            ownership.launcher_reaped = ownership.launcher_exit_code is not None
        except Exception:
            ownership.launcher_reaped = False
    ownership.launcher_exit_observed = ownership.launcher_reaped
    ownership.launcher_reaper_role = REAPER_NONE
    ownership.launcher_reap_detail = (
        "this launcher object exposes no trusted-ownership interface, so no reaper identity is "
        "claimed for it"
    )
    return killed


def abort_gated_effect(
    *,
    process: Any,
    cgroup: EffectCgroup | None,
    descriptors: tuple[int, ...] = (),
    pipes: tuple[Any, ...] = (),
    release_outcome: GateReleaseOutcome | None,
    reason: str,
    deadline: Deadline | None = None,
) -> dict[str, Any]:
    """Fail one gated effect closed, boundedly, and record what was true.

    M2-B30.  This runs on every abnormal exit from the gate sequence, whether
    the gate was positively not released or the outcome is unknown.  It is
    idempotent: a second call over already-killed, already-reaped, already-closed
    or already-removed resources performs no further destruction and reports the
    same disposition rather than a second success.

    M2-B33.  The whole path is bounded by one absolute monotonic deadline this
    controller owns, and every helper round trip inside it is bounded by a
    nested deadline that cannot outlive it.  A helper that is alive but wedged
    is bypassed rather than waited on: the local cgroup kill, the local signal,
    the local reap, and the local cgroup removal all proceed.

    M2-B34.  Termination, exit observation, reap, and reaper identity are
    recorded as four separate facts.  An empty cgroup proves the first; it is
    never presented as proof of the other three.

    It never claims the command did not run.  That claim belongs to the release
    state, which is carried through untouched and monotonically.
    """

    whole = deadline or Deadline.after_ms(ABORT_TOTAL_DEADLINE_MS, "abort_gated_effect")
    # M2-B32.  The launcher's own terminal outcome, where it has one, is the
    # truth of record: the evidence layer preserves the first terminal answer
    # rather than re-deriving a possibly weaker one at cleanup time.
    recorded = getattr(process, "release_outcome", None)
    if not isinstance(recorded, GateReleaseOutcome):
        recorded = None
    truth = monotonic_release_truth(
        recorded,
        release_outcome
        or GateReleaseOutcome(
            RELEASE_NOT_RELEASED, RELEASE_PHASE_WRITE_NOT_ATTEMPTED, "the gate was never reached"
        ),
    )

    ownership = ProcessOwnershipEvidence()
    ownership.child_subreaper = CHILD_SUBREAPER.state()
    evidence: dict[str, Any] = {
        "reason": reason,
        "release": truth.to_dict(),
        "kill_domain": None,
        "launcher_killed": False,
        "launcher_reaped": False,
        "launcher_exit_code": None,
        "quiescence": None,
        "cgroup_removal": None,
        "descriptors": None,
        "pipes_closed": 0,
        "controller_deadline_ms": ABORT_TOTAL_DEADLINE_MS,
    }

    # 1. Destroy the whole process domain.  The effect cgroup is the kill domain
    #    where one exists, so a descendant that changed session or double-forked
    #    is still reached; nothing outside this cgroup is ever signalled.  This
    #    is a local kernel mechanism and never waits on the helper.
    if cgroup is not None:
        kill_domain = cgroup.kill_domain()
        evidence["kill_domain"] = kill_domain
        ownership.process_domain_kill_requested = True
        ownership.process_domain_kill_mechanism = kill_domain.get("mechanism")

    # 2. Terminate and reap the launcher, boundedly, and record who reaped it.
    if hasattr(process, "terminate_and_reap"):
        ownership = process.terminate_and_reap(deadline=whole, evidence=ownership)
        evidence["launcher_killed"] = ownership.launcher_exit_observed
    else:
        evidence["launcher_killed"] = _legacy_terminate_and_reap(process, ownership)

    # 3. Close every descriptor this controller owns.
    evidence["descriptors"] = _close_owned_descriptors(tuple(descriptors))
    closed_pipes = 0
    for pipe in pipes:
        if pipe is None:
            continue
        try:
            if not getattr(pipe, "closed", False):
                pipe.close()
                closed_pipes += 1
        except OSError:  # pragma: no cover - defensive
            pass
    evidence["pipes_closed"] = closed_pipes

    # 4. Wait boundedly for quiescence, then remove the cgroup we own.
    if cgroup is not None:
        quiescence = cgroup.wait_quiescent(ABORT_QUIESCENCE_TIMEOUT_SECONDS)
        evidence["quiescence"] = quiescence
        ownership.cgroup_quiescent = bool(quiescence.get("quiescent"))
        cgroup.close()
        removal = cgroup.removal_evidence()
        evidence["cgroup_removal"] = removal
        ownership.effect_cgroup_removed = bool(removal.get("removed"))

    # The four lifecycle questions, kept apart, plus the legacy mirrors that
    # every existing caller and test reads.  Both come from one object, so they
    # cannot disagree.
    evidence["launcher_reaped"] = ownership.launcher_reaped
    evidence["launcher_exit_code"] = ownership.launcher_exit_code
    evidence["process_ownership"] = ownership.to_dict()
    evidence["process_domain_kill_requested"] = ownership.process_domain_kill_requested
    evidence["launcher_exit_observed"] = ownership.launcher_exit_observed
    evidence["launcher_reaper_role"] = ownership.launcher_reaper_role
    evidence["launcher_reaper_pid"] = ownership.launcher_reaper_pid
    evidence["helper_exit_observed"] = ownership.helper_exit_observed
    evidence["helper_reaped"] = ownership.helper_reaped
    evidence["cgroup_quiescent"] = ownership.cgroup_quiescent
    evidence["effect_cgroup_removed"] = ownership.effect_cgroup_removed
    evidence["deadline_expirations"] = list(ownership.deadline_expirations)
    return evidence


def _containment_evidence(status: dict[str, Any] | None, mechanism: str, cgroup: EffectCgroup | None) -> dict[str, Any]:
    """What the kernel actually held, as reported from inside the capsule.

    The values come from ``getrlimit`` calls made by the bounded child after it
    applied the bounds, so this is an observation of enforcement rather than a
    restatement of the request.  When the status document is absent the bounds
    are recorded as unobserved, never as the values that were asked for.
    Cgroup membership is claimed only when ``cgroup.active`` records a verified
    ``cgroup.procs`` membership, never from directory creation alone.
    """

    applied = None if status is None else status.get("resource_limits")
    if not isinstance(applied, dict) or not status or not status.get("resource_limits_applied"):
        return {
            "containment_mechanism": mechanism if mechanism != MECHANISM_NONE else "NONE",
            "containment_availability": "NOT_MEASURED",
            "containment_bounds": (),
            "containment_semantics": (
                "The in-capsule init did not report enforced bounds, so no containment is claimed "
                "for this effect."
            ),
        }
    described = [f"{name}={value[0]}" for name, value in sorted(applied.items()) if isinstance(value, list) and value]
    if cgroup is not None and cgroup.active:
        # ``applied`` holds values read back from the kernel after they were
        # written, so this records the bound the kernel held rather than the one
        # the controller asked for.
        described += [f"cgroup.{name}={value}" for name, value in sorted(cgroup.applied.items())]
        described.append(f"cgroup.effect_path={cgroup.path}")
        # M2-B35.  The membership that goes into durable evidence is the typed
        # observation.  A read that failed is named as a failed read, never
        # rendered as the empty list a reader would take for a clean exit.
        membership = cgroup.read_members()
        if membership.usable:
            described.append(f"cgroup.membership_verified={list(membership.pids)}")
        else:
            described.append(f"cgroup.membership_read_refused={membership.refusal_detail()}")
    return {
        "containment_mechanism": mechanism,
        "containment_availability": "OBSERVED",
        "containment_bounds": tuple(described),
        "containment_semantics": containment_semantics(mechanism),
    }


def _resource_observation(
    before: Any,
    after: Any,
    controller_peak: int,
    containment: dict[str, Any] | None = None,
) -> ResourceObservation:
    containment = containment or {
        "containment_mechanism": "NONE",
        "containment_availability": "NOT_MEASURED",
        "containment_bounds": (),
        "containment_semantics": "no resource containment was recorded for this effect",
    }
    if before is None or after is None:  # pragma: no cover - non-POSIX host
        return ResourceObservation.create(
            child_cpu_user_ms=None,
            child_cpu_user_availability="UNAVAILABLE_ON_PLATFORM",
            child_cpu_system_ms=None,
            child_cpu_system_availability="UNAVAILABLE_ON_PLATFORM",
            child_max_rss_kib=None,
            child_max_rss_availability="UNAVAILABLE_ON_PLATFORM",
            controller_peak_retained_output_bytes=controller_peak,
            controller_peak_retained_availability="OBSERVED",
            measurement_semantics=RESOURCE_MEASUREMENT_SEMANTICS,
            **containment,
        )
    user_ms = max(0, int(round((after.ru_utime - before.ru_utime) * 1000)))
    system_ms = max(0, int(round((after.ru_stime - before.ru_stime) * 1000)))
    max_rss = int(after.ru_maxrss)
    return ResourceObservation.create(
        child_cpu_user_ms=user_ms,
        child_cpu_user_availability="OBSERVED_BEST_EFFORT",
        child_cpu_system_ms=system_ms,
        child_cpu_system_availability="OBSERVED_BEST_EFFORT",
        child_max_rss_kib=max_rss if max_rss >= 0 else None,
        child_max_rss_availability="OBSERVED_BEST_EFFORT" if max_rss >= 0 else "UNAVAILABLE_ON_PLATFORM",
        controller_peak_retained_output_bytes=controller_peak,
        controller_peak_retained_availability="OBSERVED",
        measurement_semantics=RESOURCE_MEASUREMENT_SEMANTICS,
        **containment,
    )


def supervise_command(
    *,
    capsule: CapsuleSpecification,
    runtime: BoundRuntime,
    argv: tuple[str, ...],
    relative_cwd: str,
    timeout_ms: int,
    max_output_bytes: int,
    cancellation: CancellationToken | None = None,
    start_hook: Callable[[], None] | None = None,
    required_containment_mechanism: str | None = None,
) -> SupervisedProcessResult:
    """Run one command inside the shared capsule and observe it completely.

    The command never runs on the host.  It runs inside the one capsule
    :mod:`admissible.paired_runner.sandbox` constructs, as a child of an init
    that is PID 1 of a private PID namespace, against a private execution view
    bound by descriptor.  Facts that follow physically rather than by
    convention:

    * a descendant cannot leave the namespace by calling ``setsid``, by
      double-forking, or by being orphaned, because the namespace -- not the
      process group -- is the boundary;
    * quiescence is derived inside the capsule from ``ECHILD``, so
      ``descendants_reaped`` is a kernel observation and not an assertion;
    * when cgroup enforcement is required, the launcher child is created behind
      a trusted pipe gate (never a Python child-side stop hook), attached, and
      membership-verified from a real cgroup2 ``cgroup.procs`` before the gate
      is released, so the untrusted command cannot run outside the claimed
      process domain;
    * pipe EOF is *not* treated as completion.  This loop ends when the
      launcher itself is reaped, which happens only after the in-capsule init
      has observed quiescence.

    The process-domain observation arrives on a dedicated status descriptor the
    effect does not hold, so a command cannot forge or suppress it by writing to
    its own ``stdout``.
    """

    cancellation = cancellation or CancellationToken()
    start_wall, start_monotonic = _now()
    rusage_before = _rusage_children()

    if start_hook is not None:
        start_hook()

    status_read, status_write = os.pipe()
    control_read, control_write = os.pipe()
    # The syscall boundary travels as an anonymous in-memory descriptor, so the
    # filter the launcher loads has no host pathname anything could replace
    # between assembling it and loading it.
    seccomp_fd = open_program_descriptor()
    bounds = ResourceBounds.for_timeout(timeout_ms)
    delegation = cgroup_delegation()
    cgroup = EffectCgroup(delegation, bounds, f"{os.getpid()}-{start_monotonic}")
    created = cgroup.create()
    if required_containment_mechanism == MECHANISM_CGROUP_AND_RLIMIT and not created:
        for descriptor in (status_read, status_write, control_read, control_write, seccomp_fd):
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover
                pass
        raise ResourceContainmentUnavailable(
            f"cgroup subtree creation failed while readiness promised CGROUP_V2_AND_RLIMIT: {cgroup.create_error}"
        )
    launcher_argv = capsule_argv(
        capsule,
        relative_cwd=relative_cwd,
        status_fd=status_write,
        control_fd=control_read,
        seccomp_fd=seccomp_fd,
        timeout_ms=timeout_ms,
        bounds=bounds,
        command=tuple(argv),
        launcher_proc_path=runtime.launcher_proc_path,
        interpreter_fd=runtime.interpreter_fd,
        init_fd=runtime.init_fd,
        workspace_fd=runtime.workspace_fd,
    )
    pass_fds = (
        status_write,
        control_read,
        seccomp_fd,
        runtime.launcher_fd,
        runtime.interpreter_fd,
        runtime.init_fd,
        runtime.workspace_fd,
    )
    # Launch inside the private mount-namespace helper so the private tmpfs is
    # bind-mounted by a helper-local pathname.  When a cgroup subtree exists the
    # child remains behind a trusted pipe gate until membership is verified —
    # never via a Python child-side stop-before-exec hook.
    try:
        process = runtime.private_view.spawn_launcher(
            launcher_argv,
            pass_fds=pass_fds,
            await_release=cgroup.directory_present,
        )
    except Exception as error:
        for descriptor in (status_read, status_write, control_read, control_write, seccomp_fd):
            try:
                os.close(descriptor)
            except OSError:  # pragma: no cover
                pass
        cgroup.close()
        end_wall, end_monotonic = _now()
        empty_stdout = _BoundedStream("stdout", max_output_bytes)
        empty_stderr = _BoundedStream("stderr", max_output_bytes)
        stdout_observation, stdout_text, stdout_status = empty_stdout.observation()
        stderr_observation, stderr_text, stderr_status = empty_stderr.observation()
        return SupervisedProcessResult(
            process_observation=ProcessObservation.create(
                process_started=False,
                child_pid=None,
                child_process_group_id=None,
                exit_code=None,
                terminating_signal=None,
                timed_out=False,
                cancelled=False,
                start_wall_clock_unix_ms=start_wall,
                end_wall_clock_unix_ms=end_wall,
                start_monotonic_ns=start_monotonic,
                end_monotonic_ns=end_monotonic,
                duration_ns=end_monotonic - start_monotonic,
                termination_escalation=(),
                descendants_reaped=True,
                start_failure_class=type(error).__name__,
                capsule_mechanism=capsule.mechanism,
                launcher_exit_code=None,
                status_document_present=False,
                namespace_quiescent=True,
                descendants_alive_at_direct_exit=False,
                extra_descendants_reaped=0,
            ),
            stdout_observation=stdout_observation,
            stderr_observation=stderr_observation,
            resource_observation=_resource_observation(rusage_before, _rusage_children(), 0, None),
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            stdout_decode_status=stdout_status,
            stderr_decode_status=stderr_status,
        )

    launcher_pid = process.pid
    stdout_pipe = open(process.stdout_fd, "rb", buffering=0, closefd=True)
    stderr_pipe = open(process.stderr_fd, "rb", buffering=0, closefd=True)
    try:
        launcher_group = os.getpgid(launcher_pid)
    except OSError:  # pragma: no cover - the launcher exited immediately
        launcher_group = launcher_pid

    if cgroup.directory_present:
        # Child is behind the trusted pipe gate.  Attach, prove membership from
        # a real cgroup2 procs file, then release.  Failure refuses before the
        # launcher image runs and therefore before the untrusted command exists.
        owned_descriptors = (status_read, status_write, control_read, control_write, seccomp_fd)
        attached = attach_and_verify_real(cgroup, launcher_pid)
        if not attached:
            # The gate was never reached, so the launcher image never ran and
            # the untrusted command does not exist.  That is a positively
            # established NOT_RELEASED, not an inference from an exception.
            cleanup = abort_gated_effect(
                process=process,
                cgroup=cgroup,
                descriptors=owned_descriptors,
                pipes=(stdout_pipe, stderr_pipe),
                release_outcome=GateReleaseOutcome(
                    RELEASE_NOT_RELEASED,
                    RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
                    f"membership was not verified: {cgroup.attach_error}",
                ),
                reason="cgroup_membership_unverified",
            )
            if required_containment_mechanism == MECHANISM_CGROUP_AND_RLIMIT or delegation.available:
                raise ResourceContainmentUnavailable(
                    f"cgroup membership was not verified before exec: {cgroup.attach_error}",
                    release_state=RELEASE_NOT_RELEASED,
                    cleanup_evidence=cleanup,
                )
        else:
            # M2-B30.  ``release`` reports what the trusted helper acknowledged.
            # Only a completed, acknowledged gate write permits the effect to
            # continue; anything else -- including an ambiguous outcome -- aborts
            # the whole process domain and refuses completion.
            try:
                release_outcome = process.release()
            except Exception as error:  # pragma: no cover - the protocol classifies instead
                release_outcome = GateReleaseOutcome(
                    RELEASE_OUTCOME_UNKNOWN,
                    "RELEASE_CALL_RAISED",
                    f"{type(error).__name__}: {error}",
                )
            if not isinstance(release_outcome, GateReleaseOutcome):  # pragma: no cover - legacy seam
                release_outcome = GateReleaseOutcome(
                    RELEASE_OUTCOME_UNKNOWN,
                    "RELEASE_RESULT_UNCLASSIFIED",
                    f"release returned {type(release_outcome).__name__}",
                )
            if not release_outcome.released:
                cleanup = abort_gated_effect(
                    process=process,
                    cgroup=cgroup,
                    descriptors=owned_descriptors,
                    pipes=(stdout_pipe, stderr_pipe),
                    release_outcome=release_outcome,
                    reason="gate_release_not_confirmed",
                )
                raise ResourceContainmentUnavailable(
                    "the gated launcher was not confirmed released after cgroup attach: "
                    f"{release_outcome.state}/{release_outcome.phase} {release_outcome.detail}",
                    release_state=release_outcome.state,
                    cleanup_evidence=cleanup,
                )

    mechanism = effective_mechanism(
        delegation,
        membership_verified=cgroup.active,
        required_mechanism=required_containment_mechanism,
    )
    if mechanism == MECHANISM_NONE and required_containment_mechanism == MECHANISM_CGROUP_AND_RLIMIT:
        cleanup = abort_gated_effect(
            process=process,
            cgroup=cgroup,
            descriptors=(status_read, status_write, control_read, control_write, seccomp_fd),
            pipes=(stdout_pipe, stderr_pipe),
            release_outcome=GateReleaseOutcome(
                RELEASE_NOT_RELEASED,
                RELEASE_PHASE_WRITE_NOT_ATTEMPTED,
                "membership was never verified, so the gate was never released",
            ),
            reason="required_mechanism_not_proven",
        )
        raise ResourceContainmentUnavailable(
            "readiness promised CGROUP_V2_AND_RLIMIT but membership was not verified",
            release_state=RELEASE_NOT_RELEASED,
            cleanup_evidence=cleanup,
        )

    # The controller keeps only the read end of the status pipe and only the
    # write end of the control pipe.  The capsule therefore cannot forge a
    # status document and cannot hold the control pipe open on our behalf.
    os.close(status_write)
    os.close(control_read)
    os.close(seccomp_fd)

    stdout_stream = _BoundedStream("stdout", max_output_bytes)
    stderr_stream = _BoundedStream("stderr", max_output_bytes)
    streams = {stdout_pipe.fileno(): stdout_stream, stderr_pipe.fileno(): stderr_stream}
    controller_peak = 0
    status_bytes = bytearray()
    cancellation_signalled = False
    launcher_returncode: int | None = None

    # The in-capsule init enforces the requested timeout exactly.  The
    # controller keeps only a strictly larger backstop so that a launcher that
    # is itself wedged can never hang the controller, and so that the request's
    # own timeout -- not this backstop -- is what a command observes.
    backstop_ns = (
        start_monotonic
        + timeout_ms * 1_000_000
        + (GRACE_PERIOD_MS * 2 + int(CAPSULE_TEARDOWN_TIMEOUT_SECONDS * 1000)) * 1_000_000
    )

    selector = selectors.DefaultSelector()
    for pipe in (stdout_pipe, stderr_pipe):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    os.set_blocking(status_read, False)
    selector.register(status_read, selectors.EVENT_READ)

    try:
        # Pipe EOF is deliberately not a termination condition.  The loop ends
        # only when the launcher has been reaped, and the launcher exits only
        # after the in-capsule init observed ECHILD.  A command that closes both
        # of its pipes and keeps running is therefore still supervised.
        while True:
            if launcher_returncode is None:
                launcher_returncode = process.poll()

            now = time.monotonic_ns()
            if not cancellation_signalled and cancellation.cancelled:
                # Cancellation is delivered by releasing the control pipe, which
                # the init observes as EOF.  It escalates inside the namespace.
                cancellation_signalled = True
                try:
                    os.close(control_write)
                except OSError:  # pragma: no cover
                    pass
                control_write = -1
            if now >= backstop_ns:
                # The launcher outlived even the backstop.  Killing it destroys
                # the PID namespace, which the kernel guarantees takes every
                # descendant with it.
                try:
                    process.kill()
                except OSError:  # pragma: no cover
                    pass

            for key, _ in selector.select(timeout=0.05):
                descriptor = key.fd if isinstance(key.fileobj, int) else key.fileobj.fileno()
                try:
                    chunk = os.read(descriptor, READ_BLOCK_BYTES)
                except BlockingIOError:  # pragma: no cover - selector said ready
                    continue
                except OSError:
                    selector.unregister(key.fileobj)
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if descriptor == status_read:
                    if len(status_bytes) < MAX_STATUS_BYTES:
                        status_bytes += chunk[: MAX_STATUS_BYTES - len(status_bytes)]
                    continue
                streams[descriptor].feed(chunk)
                controller_peak = max(
                    controller_peak, stdout_stream.retained_bytes + stderr_stream.retained_bytes
                )

            if launcher_returncode is not None and not selector.get_map():
                break
            if launcher_returncode is not None:
                # The launcher is gone, so the namespace is gone; drain whatever
                # is still buffered in the pipes and stop.
                launcher_returncode = launcher_returncode
    finally:
        selector.close()
        for pipe in (stdout_pipe, stderr_pipe):
            try:
                pipe.close()
            except OSError:  # pragma: no cover
                pass
        try:
            os.close(status_read)
        except OSError:  # pragma: no cover
            pass
        if control_write >= 0:
            try:
                os.close(control_write)
            except OSError:  # pragma: no cover
                pass

    # Reap the launcher.  Its exit is the controller-side proof that the private
    # PID namespace no longer exists.  M2-B33: even here the wait is bounded by
    # the controller, and a helper that can no longer answer is bypassed for the
    # controller-owned kill-and-reap rather than waited on again.
    try:
        launcher_returncode = process.wait(timeout=CAPSULE_TEARDOWN_TIMEOUT_SECONDS)
    except TimeoutError:  # pragma: no cover - defensive
        if hasattr(process, "terminate_and_reap"):
            owned = process.terminate_and_reap(
                deadline=Deadline.after_ms(ABORT_TOTAL_DEADLINE_MS, "supervise_final_reap")
            )
            launcher_returncode = owned.launcher_exit_code
        else:
            process.kill()
            launcher_returncode = process.wait(timeout=CAPSULE_TEARDOWN_TIMEOUT_SECONDS)

    status = parse_capsule_status(bytes(status_bytes))
    end_wall, end_monotonic = _now()
    stdout_observation, stdout_text, stdout_status = stdout_stream.observation()
    stderr_observation, stderr_text, stderr_status = stderr_stream.observation()
    containment = _containment_evidence(status, mechanism, cgroup)
    # The namespace is gone, so the per-effect cgroup should have no members.
    # Removing a cgroup that still has live members is not reported as success.
    if not cgroup.close() and cgroup.directory_present:
        containment = {
            **containment,
            "containment_availability": "NOT_MEASURED",
            "containment_semantics": (
                "cgroup cleanup found live members; aggregate containment is not claimed after this effect"
            ),
        }

    if status is None:
        # Without the init's status document there is no process-domain
        # observation at all.  That is reported as an unobserved effect, never
        # silently completed.
        return SupervisedProcessResult(
            process_observation=ProcessObservation.create(
                process_started=True,
                child_pid=launcher_pid,
                child_process_group_id=launcher_group,
                exit_code=None,
                terminating_signal=None,
                timed_out=False,
                cancelled=cancellation.cancelled,
                start_wall_clock_unix_ms=start_wall,
                end_wall_clock_unix_ms=end_wall,
                start_monotonic_ns=start_monotonic,
                end_monotonic_ns=end_monotonic,
                duration_ns=end_monotonic - start_monotonic,
                termination_escalation=(),
                descendants_reaped=False,
                start_failure_class=None,
                capsule_mechanism=capsule.mechanism,
                launcher_exit_code=launcher_returncode,
                status_document_present=False,
                namespace_quiescent=False,
                descendants_alive_at_direct_exit=False,
                extra_descendants_reaped=0,
            ),
            stdout_observation=stdout_observation,
            stderr_observation=stderr_observation,
            resource_observation=_resource_observation(
                rusage_before, _rusage_children(), controller_peak, containment
            ),
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            stdout_decode_status=stdout_status,
            stderr_decode_status=stderr_status,
        )

    escalation = tuple(str(item) for item in status.get("termination_escalation", ()) or ())
    exit_code = status.get("direct_exit_code")
    terminating_signal = status.get("direct_terminating_signal")
    exec_failure_errno = status.get("exec_failure_errno")

    if isinstance(exec_failure_errno, int):
        # The command was never executed.  Reporting the child's 127 as though
        # the command had run and chosen to fail would be a false statement, so
        # this is a start failure with no process outcome at all.
        return SupervisedProcessResult(
            process_observation=ProcessObservation.create(
                process_started=False,
                child_pid=None,
                child_process_group_id=None,
                exit_code=None,
                terminating_signal=None,
                timed_out=False,
                cancelled=False,
                start_wall_clock_unix_ms=start_wall,
                end_wall_clock_unix_ms=end_wall,
                start_monotonic_ns=start_monotonic,
                end_monotonic_ns=end_monotonic,
                duration_ns=end_monotonic - start_monotonic,
                termination_escalation=(),
                descendants_reaped=True,
                start_failure_class=f"ExecFailed:{errno.errorcode.get(exec_failure_errno, exec_failure_errno)}",
                capsule_mechanism=capsule.mechanism,
                launcher_exit_code=launcher_returncode,
                status_document_present=True,
                namespace_quiescent=True,
                descendants_alive_at_direct_exit=False,
                extra_descendants_reaped=0,
            ),
            stdout_observation=stdout_observation,
            stderr_observation=stderr_observation,
            resource_observation=_resource_observation(
                rusage_before, _rusage_children(), controller_peak, containment
            ),
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            stdout_decode_status=stdout_status,
            stderr_decode_status=stderr_status,
        )

    return SupervisedProcessResult(
        process_observation=ProcessObservation.create(
            process_started=True,
            child_pid=launcher_pid,
            child_process_group_id=launcher_group,
            exit_code=exit_code if isinstance(exit_code, int) else None,
            terminating_signal=terminating_signal if isinstance(terminating_signal, int) else None,
            timed_out=bool(status.get("timed_out", False)),
            cancelled=bool(status.get("cancelled", False)),
            start_wall_clock_unix_ms=start_wall,
            end_wall_clock_unix_ms=end_wall,
            start_monotonic_ns=start_monotonic,
            end_monotonic_ns=end_monotonic,
            duration_ns=end_monotonic - start_monotonic,
            termination_escalation=escalation,
            # Physically verified inside the capsule from ECHILD, not assumed.
            descendants_reaped=bool(status.get("namespace_quiescent", False)),
            start_failure_class=None,
            capsule_mechanism=capsule.mechanism,
            launcher_exit_code=launcher_returncode,
            status_document_present=True,
            namespace_quiescent=bool(status.get("namespace_quiescent", False)),
            descendants_alive_at_direct_exit=bool(status.get("descendants_alive_at_direct_exit", False)),
            extra_descendants_reaped=int(status.get("extra_descendants_reaped", 0) or 0),
        ),
        stdout_observation=stdout_observation,
        stderr_observation=stderr_observation,
        resource_observation=_resource_observation(
                rusage_before, _rusage_children(), controller_peak, containment
            ),
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        stdout_decode_status=stdout_status,
        stderr_decode_status=stderr_status,
    )


def stream_fingerprint_of(name: str, data: bytes) -> Fingerprint:
    """Recompute a stream fingerprint in the same domain the supervisor uses."""

    if name not in STREAM_FINGERPRINT_DOMAINS:
        raise ValueError("unknown stream name")
    return Fingerprint("sha256", STREAM_FINGERPRINT_DOMAINS[name], hashlib.sha256(data).hexdigest()).validated()


def controller_memory_bound(max_output_bytes: int) -> int:
    """The documented upper bound on controller output retention, in bytes."""

    return 2 * max_output_bytes + CONTROLLER_FIXED_OVERHEAD_BYTES


__all__ = [
    "ABORT_QUIESCENCE_TIMEOUT_SECONDS",
    "ABORT_TOTAL_DEADLINE_MS",
    "CONTROLLER_FIXED_OVERHEAD_BYTES",
    "CancellationToken",
    "GRACE_PERIOD_MS",
    "READ_BLOCK_BYTES",
    "RESOURCE_MEASUREMENT_SEMANTICS",
    "STREAM_FINGERPRINT_DOMAINS",
    "SupervisedProcessResult",
    "TERMINATION_ESCALATION_ORDER",
    "abort_gated_effect",
    "cgroup_delegation",
    "controller_memory_bound",
    "stream_fingerprint_of",
    "supervise_command",
]
