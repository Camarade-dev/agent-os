"""The one shared observation and effect substrate used by both conditions.

There is exactly one physical execution path here.  It receives the typed
Milestone 1 objects — ``ExperimentSpecification``, ``CanonicalProposal``,
``ModeDecision``, ``EffectReservation`` — and never a mode-specific command
path.  A future DIRECT run supplies a ``DIRECT_EXECUTION`` decision and a
future GOVERNED run supplies an ``ALLOW`` decision; after that single check the
code below is the same object, the same method, and the same branches.  The
substrate refuses ``REFUSE``, ``TERMINATE_RUN``, and ``REQUIRE_CONTINUATION``
before any effect boundary is crossed.

The substrate contains no policy engine.  ``ModeDecision`` is an input, not a
computation: nothing in this module decides whether a proposal *should* be
allowed, and no test here may claim that a policy engine exists.

Confinement is fail-closed and descriptor-relative.  Every path component is
opened with ``O_NOFOLLOW`` from a directory descriptor anchored at the physical
workspace root, so no string is validated and then re-resolved against a
different object.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
from typing import Any, Callable

from .canonical import Fingerprint, fingerprint
from .durable_store import (
    FAULT_AFTER_EFFECT_BEFORE_AFTER_OBSERVATIONS,
    FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT,
    FAULT_BEFORE_FINAL_RECONCILIATION,
    FAULT_OBSERVER_FAILURE_AFTER_STARTED,
    FAULT_SANDBOX_SUPERVISOR_DEATH,
    STAGE_FINAL_RECONCILIATION_PUBLICATION,
    STAGE_LEDGER_PENDING_PUBLICATION,
    FAULT_AFTER_PROPOSAL_PUBLICATION,
    FAULT_AFTER_RESERVATION_PUBLICATION,
    FAULT_AFTER_STARTED_BEFORE_EFFECT,
    FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION,
    FAULT_BEFORE_PROPOSAL_PUBLICATION,
    FAULT_BEFORE_RESERVATION_PUBLICATION,
    FAULT_BEFORE_STARTED_PUBLICATION,
    STAGE_PROPOSAL_PUBLICATION,
    STAGE_RECONCILIATION_PUBLICATION,
    STAGE_TERMINAL_RECEIPT_PUBLICATION,
    CorruptDurableObject,
    DurableObjectStore,
    NULL_FAULT_INJECTOR,
)
from .capsule_identity import (
    CAPSULE_RUNTIME_MANIFEST_OBJECT_KIND,
    CapsuleIdentityRefused,
    CapsuleRuntimeManifest,
)
from .effect_ledger import LEDGER_OBJECT_KIND, EffectLedgerEntry, RunEffectLedger
from .git_observer import observe_git_unobserved, observe_repository
from .reconciliation import (
    FINAL_RECONCILIATION_OBJECT_KIND,
    LEDGER_PENDING_STATE,
    FinalReconciliation,
    reconcile_typed_chain,
)
from .run_index import DurableRunIndex, RunIndexBroken
from .identities import IdentityReference
from .observation import (
    SCHEMA_FILESYSTEM_OBSERVATION,
    SCHEMA_GIT_OBSERVATION,
    EffectReconciliationReport,
    FilesystemObservation,
    GitObservation,
    LifecycleRecord,
    ObservationError,
    ProcessObservation,
    PublicationReceipt,
    ResourceObservation,
    StreamObservation,
)
from .private_workspace import (
    PrivateExecutionView,
    PrivateWorkspaceError,
    apply_export,
    compute_change_set,
)
from .process_supervision import CancellationToken, supervise_command
from .cgroup_launch import RELEASE_OUTCOME_UNKNOWN
from .resource_limits import MECHANISM_CGROUP_AND_RLIMIT, ResourceContainmentUnavailable
from .runtime_binding import BoundRuntime, RuntimeBindingRefused
from .sandbox import (
    CAPSULE_WORKSPACE_PATH,
    CapsuleReadiness,
    CapsuleSpecification,
    SandboxUnavailable,
    build_capsule_specification,
    probe_capsule_readiness,
)
from .schemas import SCHEMA_VERSION as SPECIFICATION_SCHEMA_VERSION, TOOL_EFFECT_CLASSIFICATIONS
from .specification import (
    CanonicalProposal,
    EffectReceipt,
    EffectReservation,
    ExperimentSpecification,
    ModeDecision,
)
from .tool_schemas import (
    MAX_CONTENT_BYTES,
    ListFilesRequest,
    ListFilesResult,
    ReadFileRequest,
    ReadFileResult,
    RunCommandRequest,
    RunCommandResult,
    ToolRequest,
    ToolResult,
    WriteFileRequest,
    WriteFileResult,
    written_content_fingerprint,
)


TREE_FINGERPRINT_DOMAIN = f"{SCHEMA_FILESYSTEM_OBSERVATION}.tree"
GIT_STATUS_FINGERPRINT_DOMAIN = f"{SCHEMA_GIT_OBSERVATION}.status"
WORKSPACE_IDENTITY_DOMAIN = "admissible.paired_runner.m2.workspace_binding"
MAX_OBSERVED_TREE_ENTRIES = 100_000
#: Total regular-file bytes one observation may stream-hash.
MAX_OBSERVED_CONTENT_BYTES = 2 * 1024 * 1024 * 1024
WRITE_TEMPORARY_PREFIX = ".tmp-write-"
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600

#: The exact environment a supervised command receives.  Nothing is inherited,
#: so no credential, token, or provider variable can reach a child process.
SANITIZED_ENVIRONMENT_BASE = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}

OBJECT_KIND_PROPOSAL = "proposal"
OBJECT_KIND_RESERVATION = "reservation"
OBJECT_KIND_DECISION = "decision"
OBJECT_KIND_LIFECYCLE_STARTED = "lifecycle-started"
OBJECT_KIND_LIFECYCLE_TERMINAL = "lifecycle-terminal"
OBJECT_KIND_RECEIPT = "effect-receipt"
OBJECT_KIND_RECONCILIATION = "reconciliation"
OBJECT_KIND_FILESYSTEM_BEFORE = "filesystem-before"
OBJECT_KIND_FILESYSTEM_AFTER = "filesystem-after"
OBJECT_KIND_GIT_BEFORE = "git-before"
OBJECT_KIND_GIT_AFTER = "git-after"
OBJECT_KIND_PROCESS = "process-observation"
OBJECT_KIND_STDOUT = "stdout-observation"
OBJECT_KIND_STDERR = "stderr-observation"
OBJECT_KIND_RESOURCE = "resource-observation"

#: Objects that must already be durable when the first effect occurs.
PRE_EFFECT_OBJECT_KINDS = (
    OBJECT_KIND_PROPOSAL,
    OBJECT_KIND_RESERVATION,
    OBJECT_KIND_LIFECYCLE_STARTED,
)

#: The exact experiment specification schema this substrate executes.
SUPPORTED_SPECIFICATION_SCHEMA_VERSION = SPECIFICATION_SCHEMA_VERSION


class AmbiguousEffectRefused(Exception):
    """This proposal already has durable state that forbids a fresh attempt.

    Once a STARTED record is durable the effect may have occurred, so the
    substrate never replays it.  Recovery is a deliberate act performed with the
    typed reconciliation report, never an automatic retry.
    """

    def __init__(self, report: "EffectReconciliationReport") -> None:
        super().__init__(f"refusing to replay a {report.classification} effect")
        self.report = report


class WorkspaceRefusal(Exception):
    """The request is outside what this workspace binding permits."""

    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


class WorkspaceFailure(Exception):
    """The request was permitted but the host could not carry it out."""

    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


# --- descriptor-relative confinement ----------------------------------------

def _split_relative(path: str) -> tuple[tuple[str, ...], str | None]:
    """Split a validated relative POSIX path into directory parts and a leaf."""

    if path == ".":
        return (), None
    parts = tuple(path.split("/"))
    return parts[:-1], parts[-1]


def _open_child_directory(parent_fd: int, name: str) -> int:
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR}:
            # Linux reports ENOTDIR when O_DIRECTORY|O_NOFOLLOW meets a symlink,
            # so the exact refusal code comes from an lstat of the same name.
            try:
                is_link = stat.S_ISLNK(os.stat(name, dir_fd=parent_fd, follow_symlinks=False).st_mode)
            except OSError:  # pragma: no cover - it vanished between the calls
                is_link = False
            raise WorkspaceRefusal(
                "path_component_is_symlink" if is_link else "path_component_is_not_a_directory"
            ) from error
        if error.errno == errno.ENOENT:
            raise WorkspaceRefusal("path_component_absent") from error
        if error.errno == errno.EACCES:
            raise WorkspaceRefusal("path_component_not_readable") from error
        raise WorkspaceFailure("directory_open_failed") from error


class _DirectoryChain:
    """A closable chain of directory descriptors anchored at the root."""

    def __init__(self, root_fd: int) -> None:
        self._root_fd = root_fd
        self._opened: list[int] = []

    def descend(self, parts: tuple[str, ...], *, create: bool = False) -> int:
        current = self._root_fd
        for part in parts:
            if create:
                try:
                    os.mkdir(part, DIRECTORY_MODE, dir_fd=current)
                except FileExistsError:
                    pass
                except OSError as error:
                    raise WorkspaceFailure("parent_directory_creation_failed") from error
            child = _open_child_directory(current, part)
            self._opened.append(child)
            current = child
        return current

    def close(self) -> None:
        while self._opened:
            try:
                os.close(self._opened.pop())
            except OSError:  # pragma: no cover
                pass


# --- physical observations ---------------------------------------------------

def stable_identity(info: os.stat_result) -> tuple[int, ...]:
    """The inode facts that must not move while a file is being hashed.

    Size, modification time, and change time together detect a rewrite even when
    the replacement is exactly the same length; device, inode, and link count
    detect the file being swapped for a different object under the same name.
    """

    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def _hash_regular_file(directory_fd: int, name: str, *, byte_budget: int) -> tuple[str | None, int, str | None]:
    """Stream-hash one regular file without ever following a symlink.

    Returns ``(content_fingerprint_hex, bytes_read, error)``.  The file is
    opened ``O_NOFOLLOW|O_NONBLOCK`` and re-checked with ``fstat`` on the open
    descriptor, so a name that is swapped for a symlink, FIFO, or device between
    the directory scan and the open cannot make the observer follow it or block
    on it.

    The descriptor is ``fstat``-ed again *after* the last byte is read and the
    two identities are compared.  Without that, a writer that changed the file
    while it was being read produced a digest of a mixture of two versions --
    bytes that never existed together on disk -- and the observation reported it
    as complete.  A moved identity is an explicit observation error instead.
    """

    try:
        handle = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd
        )
    except OSError as error:
        return None, 0, f"open_failed:{errno.errorcode.get(error.errno, error.errno)}"
    try:
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode):
            # The entry changed identity after the scan; that is an observation
            # error, never a silently skipped entry.
            return None, 0, "entry_is_no_longer_a_regular_file"
        before = stable_identity(info)
        digest = hashlib.sha256()
        read_total = 0
        while True:
            if read_total > byte_budget:
                return None, read_total, "content_byte_budget_exhausted"
            try:
                chunk = os.read(handle, 1 << 20)
            except BlockingIOError:  # pragma: no cover - regular files never block
                return None, read_total, "read_would_block"
            except OSError as error:
                return None, read_total, f"read_failed:{errno.errorcode.get(error.errno, error.errno)}"
            if not chunk:
                break
            digest.update(chunk)
            read_total += len(chunk)
        try:
            after = stable_identity(os.fstat(handle))
        except OSError as error:  # pragma: no cover - the descriptor is ours
            return None, read_total, f"restat_failed:{errno.errorcode.get(error.errno, error.errno)}"
        if after != before:
            return None, read_total, "entry_changed_while_it_was_being_hashed"
        return digest.hexdigest(), read_total, None
    finally:
        os.close(handle)


def observe_filesystem(
    root_fd: int,
    *,
    phase: str,
    max_entries: int = MAX_OBSERVED_TREE_ENTRIES,
    max_content_bytes: int = MAX_OBSERVED_CONTENT_BYTES,
) -> FilesystemObservation:
    """Fingerprint the workspace tree *including file contents*.

    The Milestone 2 observer bound only ``(path, kind, size, mode)``, so a
    same-size content substitution -- the single easiest way to alter a
    workspace without being seen -- left the tree fingerprint unchanged.  This
    observer streams the bytes of every regular file into the fingerprint and
    records a symlink's target bytes without following the link, so the
    fingerprint changes whenever the tree's observable content changes.

    Nothing is skipped silently.  Every entry that cannot be listed, stated,
    opened, or read is recorded as an explicit error, and any observation that
    carries an error or hits a limit is marked incomplete so it can never serve
    as a final repository fingerprint.
    """

    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    endpoints: list[str] = []
    total_bytes = 0
    hashed_files = 0
    truncated = False
    completeness = "COMPLETE"
    remaining_budget = max_content_bytes
    stack: list[tuple[int, str, bool]] = [(root_fd, "", False)]
    try:
        while stack:
            directory_fd, prefix, owned = stack.pop()
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError as error:
                # An unreadable directory is recorded, not quietly treated as
                # empty.  Claiming OBSERVED over an unread subtree would be a
                # false statement about the workspace.
                errors.append(
                    f"{prefix or '.'}:listdir_failed:{errno.errorcode.get(error.errno, error.errno)}"
                )
                completeness = "INCOMPLETE_OBSERVATION_ERROR"
                names = []
            for name in names:
                relative = f"{prefix}{name}"
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    # The entry disappeared or became unreadable between the
                    # listing and the stat.  That is a recorded fact.
                    errors.append(
                        f"{relative}:stat_failed:{errno.errorcode.get(error.errno, error.errno)}"
                    )
                    completeness = "INCOMPLETE_OBSERVATION_ERROR"
                    continue
                if len(entries) >= max_entries:
                    truncated = True
                    if completeness == "COMPLETE":
                        completeness = "INCOMPLETE_ENTRY_LIMIT"
                    continue

                entry: dict[str, Any] = {
                    "path": relative,
                    "mode": stat.S_IMODE(info.st_mode),
                    "content_fingerprint": None,
                    "symlink_target_hex": None,
                    "size": 0,
                }
                if stat.S_ISDIR(info.st_mode):
                    entry["kind"] = "directory"
                elif stat.S_ISLNK(info.st_mode):
                    entry["kind"] = "symlink"
                    try:
                        # The target *bytes* are bound; the link is never
                        # followed, so a retarget is visible as a change.
                        target = os.readlink(name, dir_fd=directory_fd)
                        entry["symlink_target_hex"] = target.encode(
                            "utf-8", "surrogateescape"
                        ).hex()
                    except OSError as error:
                        errors.append(
                            f"{relative}:readlink_failed:{errno.errorcode.get(error.errno, error.errno)}"
                        )
                        completeness = "INCOMPLETE_OBSERVATION_ERROR"
                elif stat.S_ISREG(info.st_mode):
                    entry["kind"] = "regular_file"
                    entry["size"] = info.st_size
                    total_bytes += info.st_size
                    content, read_total, error_detail = _hash_regular_file(
                        directory_fd, name, byte_budget=remaining_budget
                    )
                    remaining_budget -= read_total
                    if content is None:
                        errors.append(f"{relative}:{error_detail}")
                        if error_detail == "content_byte_budget_exhausted":
                            if completeness == "COMPLETE":
                                completeness = "INCOMPLETE_BYTE_LIMIT"
                        else:
                            completeness = "INCOMPLETE_OBSERVATION_ERROR"
                    else:
                        entry["content_fingerprint"] = content
                        hashed_files += 1
                else:
                    # A FIFO, socket, or device is recorded by its exact type and
                    # never opened, so a hostile special file cannot block the
                    # observer.  The type matters: each of these is a host-backed
                    # IPC endpoint or device node, and lumping them together as
                    # "other" is what let a pathname Unix socket look like an
                    # ordinary anomaly rather than a bridge across the capsule.
                    entry["kind"] = _special_entry_kind(info.st_mode)
                    endpoints.append(f"{relative}:{entry['kind']}")

                entries.append(entry)
                if entry["kind"] == "directory":
                    try:
                        child = _open_child_directory(directory_fd, name)
                    except (WorkspaceRefusal, WorkspaceFailure) as refusal:
                        errors.append(f"{relative}:descend_failed:{refusal.error_code}")
                        completeness = "INCOMPLETE_OBSERVATION_ERROR"
                        continue
                    stack.append((child, f"{relative}/", True))
            if owned:
                os.close(directory_fd)
    finally:
        for directory_fd, _, owned in stack:
            if owned:
                try:
                    os.close(directory_fd)
                except OSError:  # pragma: no cover
                    pass

    entries.sort(key=lambda item: item["path"])
    availability = "OBSERVED" if completeness == "COMPLETE" else "OBSERVED_BEST_EFFORT"
    return FilesystemObservation.create(
        phase=phase,
        entry_count=len(entries),
        total_regular_file_bytes=total_bytes,
        truncated=truncated,
        tree_fingerprint=fingerprint(
            {"entries": entries, "errors": sorted(errors)}, domain=TREE_FINGERPRINT_DOMAIN
        ),
        availability=availability,
        completeness=completeness,
        content_hashed_file_count=hashed_files,
        error_count=len(errors),
        errors=tuple(sorted(errors)),
        ipc_endpoint_count=len(endpoints),
        ipc_endpoints=tuple(sorted(endpoints)),
    )


def _special_entry_kind(mode: int) -> str:
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "other"


class WorkspaceIpcEndpointRefused(Exception):
    """The workspace holds a host-backed IPC endpoint, so no process may start.

    A pathname ``AF_UNIX`` socket in the workspace is reachable from inside the
    capsule *despite* the unshared network namespace, and a peer on the host side
    of it can hand the capsuled process an open descriptor with ``SCM_RIGHTS``
    for any file that peer can open -- including one the capsule's mount
    namespace does not contain.  A FIFO is the same bridge without the
    descriptor passing, and a device node is a direct host object.

    None of these may exist in a workspace at the moment a process is started
    inside it.  This refusal happens before the effect boundary is crossed, so a
    workspace carrying an endpoint produces no effect at all.
    """

    def __init__(self, endpoints: tuple[str, ...]) -> None:
        super().__init__(f"the workspace contains host-backed IPC endpoints: {list(endpoints)}")
        self.endpoints = endpoints


def scan_workspace_ipc_endpoints(root_fd: int, *, max_entries: int = MAX_OBSERVED_TREE_ENTRIES) -> tuple[str, ...]:
    """List every socket, FIFO, and device node in the workspace tree.

    This is the cheap admission scan: it stats, it never opens, and it never
    hashes, so it can run immediately before a capsuled process starts without
    re-reading the workspace's content.
    """

    found: list[str] = []
    scanned = 0
    stack: list[tuple[int, str, bool]] = [(root_fd, "", False)]
    try:
        while stack:
            directory_fd, prefix, owned = stack.pop()
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError:
                names = []
            for name in names:
                relative = f"{prefix}{name}"
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    continue
                scanned += 1
                if scanned > max_entries:
                    # A tree this large cannot be admitted on a partial scan: an
                    # unscanned subtree could hold the exact endpoint this exists
                    # to find, so the limit itself is reported as an endpoint.
                    found.append(f"{relative}:scan_limit_reached")
                    return tuple(sorted(found))
                if stat.S_ISDIR(info.st_mode):
                    try:
                        child = _open_child_directory(directory_fd, name)
                    except (WorkspaceRefusal, WorkspaceFailure):
                        continue
                    stack.append((child, f"{relative}/", True))
                    continue
                if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    continue
                found.append(f"{relative}:{_special_entry_kind(info.st_mode)}")
            if owned:
                os.close(directory_fd)
    finally:
        for directory_fd, _, owned in stack:
            if owned:
                try:
                    os.close(directory_fd)
                except OSError:  # pragma: no cover
                    pass
    return tuple(sorted(found))


def require_no_workspace_ipc_endpoints(root_fd: int) -> None:
    """Refuse to start a capsuled process over a workspace holding an endpoint."""

    endpoints = scan_workspace_ipc_endpoints(root_fd)
    if endpoints:
        raise WorkspaceIpcEndpointRefused(endpoints)


def observe_git(root: Path, root_fd: int, *, phase: str) -> GitObservation:
    """Observe Git state by reading it, never by running it.

    The Milestone 2 observer executed ``git status`` behind a list of ``-c``
    overrides that disabled every *known* way a repository could name a program.
    The independent audit showed that list is unclosable: a repository selects an
    arbitrary filter driver by name through ``.gitattributes`` and defines it in
    its own configuration, and ``git status`` must run that driver to decide
    whether a working-tree file matches the index.  The observation therefore
    executed repository-chosen code -- after the durable STARTED record, during
    what the evidence called an observation, with no proposal covering it.

    There is no denylist here and no ``git`` process.  The repaired observer in
    :mod:`admissible.paired_runner.git_observer` parses refs, the index, and the
    object store directly, and fails closed with an explicit availability
    whenever the answer would require running something.
    """

    return observe_repository(root, root_fd, phase=phase)


# --- workspace binding -------------------------------------------------------

class EvidenceRootIsolationError(ValueError):
    """The workspace and the durable evidence root are not physically disjoint."""


@dataclass(frozen=True)
class RootIdentity:
    """The exact inode identity of one root, recorded so it can be rechecked."""

    path: str
    device: int
    inode: int
    mode: int

    @classmethod
    def of_descriptor(cls, path: Path, descriptor: int) -> "RootIdentity":
        info = os.fstat(descriptor)
        return cls(path=str(path), device=info.st_dev, inode=info.st_ino, mode=stat.S_IMODE(info.st_mode))

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "device": self.device, "inode": self.inode, "mode": self.mode}

    def matches_descriptor(self, descriptor: int) -> bool:
        info = os.fstat(descriptor)
        return info.st_dev == self.device and info.st_ino == self.inode


def _open_root_directory(path: Path, label: str) -> int:
    """Open a canonical, non-symlink directory root and keep the descriptor."""

    if not path.is_absolute():
        raise EvidenceRootIsolationError(f"the {label} must be an absolute physical path")
    if path.is_symlink():
        raise EvidenceRootIsolationError(f"the {label} itself must not be a symlink")
    if Path(os.path.realpath(path)) != path:
        raise EvidenceRootIsolationError(f"the {label} must equal its canonical resolved path")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):  # pragma: no cover - O_DIRECTORY guarantees it
            raise EvidenceRootIsolationError(f"the {label} must be a directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def enforce_evidence_root_isolation(workspace: Path, store_root: Path) -> tuple[RootIdentity, RootIdentity]:
    """Prove the workspace and the evidence root are disjoint physical objects.

    Path strings are not trusted.  Both roots are opened as descriptors, their
    canonical paths are compared for containment in either direction, and their
    ``(device, inode)`` identities are compared so that a hard link, a bind
    alias, or a rename that makes two names refer to the same directory is
    caught even though the strings differ.
    """

    workspace_fd = _open_root_directory(workspace, "workspace root")
    try:
        store_fd = _open_root_directory(store_root, "durable store root")
    except BaseException:
        os.close(workspace_fd)
        raise
    try:
        workspace_identity = RootIdentity.of_descriptor(workspace, workspace_fd)
        store_identity = RootIdentity.of_descriptor(store_root, store_fd)
        if (workspace_identity.device, workspace_identity.inode) == (
            store_identity.device,
            store_identity.inode,
        ):
            raise EvidenceRootIsolationError(
                "the workspace and the durable store are the same physical directory"
            )
        if workspace == store_root:
            raise EvidenceRootIsolationError("the workspace and the durable store must be disjoint")
        if _is_within(store_root, workspace):
            raise EvidenceRootIsolationError("the durable store must not be inside the workspace")
        if _is_within(workspace, store_root):
            raise EvidenceRootIsolationError("the workspace must not be inside the durable store")
        # The platform contract requires an owner-only evidence root, so a
        # same-UID process elsewhere on the host cannot be invited in by mode.
        if store_identity.mode & 0o077:
            raise EvidenceRootIsolationError(
                "the durable store root must not be group- or world-accessible"
            )
        return workspace_identity, store_identity
    finally:
        os.close(workspace_fd)
        os.close(store_fd)


def _is_within(candidate: Path, ancestor: Path) -> bool:
    try:
        candidate.relative_to(ancestor)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class WorkspaceBinding:
    """A strict runtime binding between a physical root and an experiment."""

    physical_root: Path
    canonical_root: Path
    working_root_identity: IdentityReference
    scope_identity: IdentityReference
    experiment_specification_fingerprint: Fingerprint
    initial_filesystem_observation: FilesystemObservation
    git_present: bool
    initial_git_observation: GitObservation
    root_fd: int
    workspace_root_identity: RootIdentity
    store_root_identity: RootIdentity
    capsule: CapsuleSpecification
    capsule_readiness: CapsuleReadiness

    @classmethod
    def bind(
        cls,
        root: str | os.PathLike[str],
        specification: ExperimentSpecification,
        *,
        evidence_root: str | os.PathLike[str],
        readiness: CapsuleReadiness | None = None,
    ) -> "WorkspaceBinding":
        """Bind a workspace without executing anything at all.

        Nothing in this method starts a process.  The Milestone 2 binding ran a
        Git observation here, which meant a repository-controlled
        ``core.fsmonitor`` program executed before any proposal was durable --
        an effect with no proposal, no decision, and no evidence.  Binding is
        now pure syscalls, and the first Git observation happens only after the
        proposal has been published.
        """

        specification.validated()
        physical = Path(root)
        evidence = Path(evidence_root)
        workspace_identity, store_identity = enforce_evidence_root_isolation(physical, evidence)

        capsule_readiness = (readiness or probe_capsule_readiness()).require()
        capsule = build_capsule_specification(
            workspace_host_path=physical,
            evidence_root=evidence,
            readiness=capsule_readiness,
        )

        root_fd = os.open(physical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            filesystem = observe_filesystem(root_fd, phase="INITIAL")
            git = observe_git_unobserved(
                "INITIAL", "NOT_OBSERVED_BEFORE_DURABLE_PROPOSAL"
            ) if (physical / ".git").exists() else GitObservation.create(
                phase="INITIAL", availability="REPOSITORY_ABSENT", repository_present=False
            )
            return cls(
                physical_root=physical,
                canonical_root=Path(os.path.realpath(physical)),
                working_root_identity=specification.working_root_identity,
                scope_identity=specification.scope_identity,
                experiment_specification_fingerprint=specification.specification_fingerprint,
                initial_filesystem_observation=filesystem,
                git_present=git.repository_present,
                initial_git_observation=git,
                root_fd=root_fd,
                workspace_root_identity=workspace_identity,
                store_root_identity=store_identity,
                capsule=capsule,
                capsule_readiness=capsule_readiness,
            )
        except BaseException:
            os.close(root_fd)
            raise

    def recheck_root_identity(self) -> None:
        """Re-prove the open root is still the exact directory that was bound.

        A rename or replacement of the workspace root between binding and use
        would otherwise let a later operation act on a different directory that
        happens to carry the same path string.
        """

        if not self.workspace_root_identity.matches_descriptor(self.root_fd):
            raise EvidenceRootIsolationError(
                "the bound workspace root descriptor no longer matches its recorded inode identity"
            )

    @property
    def capsule_runtime_manifest(self) -> CapsuleRuntimeManifest:
        manifest = self.capsule_readiness.runtime_manifest
        if manifest is None:  # pragma: no cover - readiness refuses without one
            raise CapsuleIdentityRefused("this binding carries no capsule runtime manifest")
        return manifest

    def recheck_capsule_runtime_identity(self) -> CapsuleRuntimeManifest:
        """Re-derive the capsule's byte identity and refuse any substitution.

        The launcher is resolved through ``PATH`` again as part of this, so a
        shadowing entry that would be found *now* is caught even when the
        recorded absolute path still holds the original bytes.
        """

        manifest = self.capsule_runtime_manifest
        manifest.recheck(resolver=lambda: shutil.which("bwrap") or "")
        return manifest

    def validate_for_specification(self, specification: ExperimentSpecification) -> "WorkspaceBinding":
        specification.validated()
        if self.experiment_specification_fingerprint != specification.specification_fingerprint:
            raise ValueError("the workspace is bound to a different experiment specification")
        if self.working_root_identity != specification.working_root_identity:
            raise ValueError("the workspace working-root identity differs from the specification")
        if self.scope_identity != specification.scope_identity:
            raise ValueError("the workspace scope identity differs from the specification")
        return self

    def binding_fingerprint(self) -> Fingerprint:
        return fingerprint(
            {
                "canonical_root": str(self.canonical_root),
                "working_root_identity": self.working_root_identity.to_dict(),
                "scope_identity": self.scope_identity.to_dict(),
                "experiment_specification_fingerprint": self.experiment_specification_fingerprint.to_dict(),
                "initial_filesystem_observation": self.initial_filesystem_observation.to_dict(),
                "git_present": self.git_present,
                "initial_git_observation": self.initial_git_observation.to_dict(),
                "workspace_root_identity": self.workspace_root_identity.to_dict(),
                "store_root_identity": self.store_root_identity.to_dict(),
                "capsule": self.capsule.to_dict(),
            },
            domain=WORKSPACE_IDENTITY_DOMAIN,
        )

    def chain(self) -> _DirectoryChain:
        return _DirectoryChain(self.root_fd)

    def physical_path_of(self, relative: str) -> Path:
        """A host path for a relative POSIX path already proven symlink-free."""

        return self.physical_root if relative == "." else self.physical_root / relative

    def close(self) -> None:
        try:
            os.close(self.root_fd)
        except OSError:  # pragma: no cover
            pass


# --- the four tool implementations ------------------------------------------

@dataclass
class _EffectPreparation:
    """Physical handles opened *before* STARTED, so refusal is truly pre-effect.

    Milestone 2 published a durable STARTED record, crossed the boundary, and
    only then discovered that the target was missing or was a symlink.  The
    resulting evidence contradicted itself: the lifecycle said an effect had
    started and the ledger said the boundary was crossed, while the receipt said
    ``REFUSED`` with ``effect_started=false``.

    Preparation resolves every physical precondition first and *retains the
    descriptors it proved*.  A refusal therefore happens before any STARTED
    record exists, and the execution that follows acts on the very objects that
    were checked -- not on a path string that could have been swapped in
    between.

    For ``run_command``, preparation also materialises the private execution
    view from the authorized source.  The effect therefore never depends on a
    live writable bind of the host workspace.
    """

    chain: _DirectoryChain
    parent_fd: int = -1
    handle: int = -1
    refusal: ToolResult | None = None
    private_view: PrivateExecutionView | None = None
    #: M2-B43.  The private view's last closure evidence.
    private_view_cleanup: dict[str, Any] | None = None

    def close(self) -> None:
        if self.handle >= 0:
            try:
                os.close(self.handle)
            except OSError:  # pragma: no cover
                pass
            self.handle = -1
        if self.private_view is not None:
            # M2-B43.  The view is dropped only once its helper is positively
            # reaped and its ownership ended.  Dropping the reference over an
            # incomplete cleanup would make the retry unreachable and leave an
            # unreaped child of this controller with nobody holding its handle.
            self.private_view_cleanup = self.private_view.close()
            if self.private_view_cleanup.get("cleanup_complete"):
                self.private_view = None
        self.chain.close()


def _refusal_result(request: ToolRequest, error: Exception) -> ToolResult:
    outcome = "REFUSED" if isinstance(error, WorkspaceRefusal) else "FAILED"
    code = getattr(error, "error_code", "preparation_failed")
    kind = type(request).__name__
    if kind == "ListFilesRequest":
        return ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, outcome=outcome, error_code=code
        )
    if kind == "ReadFileRequest":
        return ReadFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome=outcome, error_code=code
        )
    if kind == "WriteFileRequest":
        return WriteFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome=outcome, error_code=code
        )
    return RunCommandResult.create(
        request_fingerprint=request.request_fingerprint,
        outcome=outcome,
        process_started=False,
        exit_code=None,
        error_code=code,
    )


def prepare_effect(binding: WorkspaceBinding, request: ToolRequest) -> _EffectPreparation:
    """Resolve and retain every physical precondition before STARTED exists."""

    binding.recheck_root_identity()
    preparation = _EffectPreparation(chain=binding.chain())
    try:
        if isinstance(request, ListFilesRequest):
            parts, leaf = _split_relative(request.path)
            descend = parts if leaf is None else parts + (leaf,)
            preparation.parent_fd = preparation.chain.descend(descend)
        elif isinstance(request, ReadFileRequest):
            parts, leaf = _split_relative(request.path)
            if leaf is None:
                raise WorkspaceRefusal("path_is_directory")
            preparation.parent_fd = preparation.chain.descend(parts)
            preparation.handle = _open_regular_for_read(preparation.parent_fd, leaf)
        elif isinstance(request, WriteFileRequest):
            parts, leaf = _split_relative(request.path)
            if leaf is None:
                raise WorkspaceRefusal("path_is_directory")
            try:
                preparation.parent_fd = preparation.chain.descend(parts)
            except WorkspaceRefusal as refusal:
                if refusal.error_code == "path_component_absent" and not request.create_parents:
                    raise WorkspaceRefusal("parent_directory_absent") from refusal
                if refusal.error_code != "path_component_absent":
                    raise
                # The parents are absent but their creation was authorized, so
                # this is not a refusal.  The directories are created after
                # STARTED, because creating them is itself a mutation.
                preparation.parent_fd = -1
                return preparation
            _check_write_target(preparation.parent_fd, leaf)
        elif isinstance(request, RunCommandRequest):
            parts, leaf = _split_relative(request.cwd)
            descend = parts if leaf is None else parts + (leaf,)
            preparation.parent_fd = preparation.chain.descend(descend)
            physical_cwd = binding.physical_path_of(request.cwd)
            if Path(os.path.realpath(physical_cwd)) != physical_cwd:
                raise WorkspaceRefusal("cwd_is_not_physically_under_the_root")
            # Refuse a source that already holds an IPC endpoint, then materialise
            # the private execution view the effect will actually see.  A host
            # FIFO created after this point lands in the authorized workspace,
            # not in the private view.
            try:
                require_no_workspace_ipc_endpoints(binding.root_fd)
            except WorkspaceIpcEndpointRefused as refusal:
                raise WorkspaceRefusal("workspace_contains_a_host_ipc_endpoint") from refusal
            try:
                preparation.private_view = PrivateExecutionView.materialize(
                    binding.physical_root, binding.root_fd
                )
            except PrivateWorkspaceError as error:
                raise WorkspaceRefusal(f"private_workspace_{error.code}") from error
            try:
                require_no_workspace_ipc_endpoints(preparation.private_view.view_fd)
            except WorkspaceIpcEndpointRefused as refusal:
                raise WorkspaceRefusal("private_view_contains_an_ipc_endpoint") from refusal
        else:  # pragma: no cover - the typed union is closed
            raise TypeError("unknown typed tool request")
    except (WorkspaceRefusal, WorkspaceFailure) as error:
        preparation.refusal = _refusal_result(request, error)
    return preparation


def _open_regular_for_read(parent_fd: int, leaf: str) -> int:
    """Open a regular file without following links and without blocking."""

    try:
        handle = os.open(
            leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd
        )
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise WorkspaceRefusal("final_path_is_symlink") from error
        if error.errno == errno.ENOENT:
            raise WorkspaceRefusal("path_absent") from error
        if error.errno == errno.EISDIR:
            raise WorkspaceRefusal("path_is_directory") from error
        if error.errno == errno.EACCES:
            raise WorkspaceRefusal("path_not_readable") from error
        if error.errno == errno.ENXIO:
            raise WorkspaceRefusal("path_is_not_a_regular_file") from error
        raise WorkspaceFailure("file_open_failed") from error
    try:
        mode = os.fstat(handle).st_mode
        if stat.S_ISDIR(mode):
            raise WorkspaceRefusal("path_is_directory")
        if not stat.S_ISREG(mode):
            raise WorkspaceRefusal("path_is_not_a_regular_file")
    except BaseException:
        os.close(handle)
        raise
    return handle


def _check_write_target(parent_fd: int, leaf: str) -> None:
    try:
        existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise WorkspaceFailure("target_stat_failed") from error
    if stat.S_ISLNK(existing.st_mode):
        raise WorkspaceRefusal("final_path_is_symlink")
    if stat.S_ISDIR(existing.st_mode):
        raise WorkspaceRefusal("path_is_directory")
    if not stat.S_ISREG(existing.st_mode):
        raise WorkspaceRefusal("path_is_not_a_regular_file")



def _list_files(
    binding: WorkspaceBinding, request: ListFilesRequest, preparation: "_EffectPreparation"
) -> ListFilesResult:
    """List entries under the already-proven directory descriptor."""

    collected: list[str] = []
    over_limit = False
    base_fd = preparation.parent_fd
    prefix = "" if request.path == "." else f"{request.path}/"
    stack: list[tuple[int, str, bool]] = [(base_fd, prefix, False)]
    limit = request.max_entries
    try:
        while stack:
            directory_fd, current_prefix, owned = stack.pop()
            for name in sorted(os.listdir(directory_fd), reverse=True):
                relative = f"{current_prefix}{name}"
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    continue
                collected.append(relative)
                if request.recursive and stat.S_ISDIR(info.st_mode):
                    # lstat above means an escaping symlinked directory is
                    # listed but never traversed.
                    try:
                        child = _open_child_directory(directory_fd, name)
                    except (WorkspaceRefusal, WorkspaceFailure):
                        continue
                    stack.append((child, f"{relative}/", True))
            if owned:
                os.close(directory_fd)
            if len(collected) > limit * 4 + 64:
                over_limit = True
                break
    except OSError:
        return ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, outcome="FAILED", error_code="listing_failed"
        )
    finally:
        for directory_fd, _, owned in stack:
            if owned:
                try:
                    os.close(directory_fd)
                except OSError:  # pragma: no cover
                    pass

    entries = sorted(set(collected))
    truncated = over_limit or len(entries) > request.max_entries
    if truncated:
        entries = entries[: request.max_entries]
    return ListFilesResult.create(
        request_fingerprint=request.request_fingerprint,
        outcome="OK",
        entries=tuple(entries),
        truncated=truncated,
    )


def _read_file(
    binding: WorkspaceBinding, request: ReadFileRequest, preparation: "_EffectPreparation"
) -> ReadFileResult:
    """Read the already-opened regular file.

    The descriptor was opened during preparation and proven to be a regular
    file with ``fstat``, so nothing here re-resolves a path and no FIFO,
    socket, device, or directory can be substituted between the check and the
    read.
    """

    handle = preparation.handle
    try:
        raw = b""
        while len(raw) <= MAX_CONTENT_BYTES:
            try:
                chunk = os.read(handle, 1 << 20)
            except BlockingIOError as error:  # pragma: no cover - regular files never block
                raise WorkspaceFailure("read_would_block") from error
            if not chunk:
                break
            raw += chunk
        if len(raw) > MAX_CONTENT_BYTES:
            raise WorkspaceFailure("file_exceeds_content_cap")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            # Fail closed rather than silently replacing bytes.
            raise WorkspaceFailure("non_utf8_file") from error
    except WorkspaceRefusal as refusal:
        return ReadFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="REFUSED", error_code=refusal.error_code
        )
    except WorkspaceFailure as failure:
        return ReadFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="FAILED", error_code=failure.error_code
        )
    except OSError:
        return ReadFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="FAILED", error_code="read_failed"
        )

    lines = text.splitlines(keepends=True)
    start = (request.start_line or 1) - 1
    selected = lines[start : start + request.max_lines]
    content = "".join(selected)
    truncated = len(selected) == request.max_lines and len(lines) > start + len(selected)
    return ReadFileResult.create(
        request_fingerprint=request.request_fingerprint,
        outcome="OK",
        content=content,
        truncated=truncated,
    )


def _write_file(
    binding: WorkspaceBinding, request: WriteFileRequest, preparation: "_EffectPreparation"
) -> WriteFileResult:
    """Write atomically beneath the already-proven parent descriptor."""

    parts, leaf = _split_relative(request.path)
    payload = request.content.encode("utf-8", "strict")
    temporary: str | None = None
    parent_fd = preparation.parent_fd
    own_chain: _DirectoryChain | None = None
    try:
        if parent_fd < 0:
            # Preparation proved the parents were absent and that creating them
            # was authorized.  Creating them is a mutation, so it happens here,
            # after STARTED, and never during preparation.
            own_chain = binding.chain()
            parent_fd = own_chain.descend(parts, create=True)

        temporary = f"{WRITE_TEMPORARY_PREFIX}{os.getpid()}-{time.monotonic_ns()}"
        handle = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=parent_fd
        )
        try:
            written = 0
            while written < len(payload):
                written += os.write(handle, payload[written:])
            os.fsync(handle)
        finally:
            os.close(handle)
        # Atomic replacement.  rename() replaces the destination name itself and
        # never writes through a symlink, so the preparation check above is a
        # refusal policy rather than the safety mechanism.
        os.rename(temporary, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)
        os.fsync(binding.root_fd)
    except WorkspaceRefusal as refusal:
        return WriteFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="REFUSED", error_code=refusal.error_code
        )
    except WorkspaceFailure as failure:
        return WriteFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="FAILED", error_code=failure.error_code
        )
    except OSError:
        return WriteFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="FAILED", error_code="write_failed"
        )
    finally:
        if temporary is not None and parent_fd >= 0:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:  # pragma: no cover
                pass
        if own_chain is not None:
            own_chain.close()

    return WriteFileResult.create(
        request_fingerprint=request.request_fingerprint,
        outcome="OK",
        bytes_written=len(payload),
        written_content_fingerprint=written_content_fingerprint(request.content),
    )


@dataclass(frozen=True)
class _CommandExecution:
    result: RunCommandResult
    process_observation: ProcessObservation | None
    stdout_observation: StreamObservation | None
    stderr_observation: StreamObservation | None
    resource_observation: ResourceObservation | None
    timed_out: bool
    cancelled: bool


def _run_command(
    binding: WorkspaceBinding,
    request: RunCommandRequest,
    *,
    preparation: _EffectPreparation,
    cancellation: CancellationToken | None,
    start_hook: Callable[[], None] | None,
    durable_root: Path | None = None,
    causal: dict[str, str] | None = None,
) -> _CommandExecution:
    """Run the request inside the capsule against a private execution view.

    The private view was materialised during preparation, before STARTED.  The
    effect never sees the live authorized host workspace: only a trusted export
    of a closed change set mutates that workspace after quiescence.
    """

    binding.recheck_root_identity()
    private_view = preparation.private_view
    if private_view is None:
        return _command_start_failure(request, "private_workspace_absent")
    # The preparation close must not destroy the view while we still hold it;
    # ownership transfers to the bound runtime for the duration of the launch.
    preparation.private_view = None
    runtime: BoundRuntime | None = None
    try:
        try:
            runtime = BoundRuntime.bind(
                manifest=binding.capsule_runtime_manifest,
                private_view=private_view,
                resolver=lambda: shutil.which("bwrap") or "",
            )
        except RuntimeBindingRefused:
            private_view.close()
            return _command_start_failure(request, "runtime_identity_bind_refused")

        required_mechanism = binding.capsule_readiness.containment_mechanism
        try:
            supervised = supervise_command(
                capsule=binding.capsule,
                runtime=runtime,
                argv=request.argv,
                relative_cwd=request.cwd,
                timeout_ms=request.timeout_ms,
                max_output_bytes=request.max_output_bytes,
                cancellation=cancellation,
                start_hook=start_hook,
                required_containment_mechanism=required_mechanism,
            )
        except ResourceContainmentUnavailable as refusal:
            # M2-B30.  When the trusted gate's release outcome is unknown this
            # effect may not be recorded as "never started": the controller does
            # not know which side of the gate write the helper failed on.  The
            # process domain has been killed, reaped, and cleaned up, but the
            # execution outcome is reported as unknown rather than as absent.
            if getattr(refusal, "release_state", None) == RELEASE_OUTCOME_UNKNOWN:
                cleanup = refusal.cleanup_evidence
                quiescent = bool((cleanup.get("quiescence") or {}).get("quiescent", False))
                removal = bool((cleanup.get("cgroup_removal") or {}).get("removed", False))
                return _command_start_failure(
                    request,
                    "cgroup_gate_release_outcome_unknown",
                    execution_outcome_semantics=(
                        "EXECUTION_OUTCOME_UNKNOWN: the trusted gate write may have completed "
                        "before the acknowledgement was lost, so it is not claimed that the "
                        "proposed command never executed.  The effect process domain was killed "
                        f"as a cgroup kill domain (quiescent={quiescent}), the launcher was "
                        f"reaped ({bool(cleanup.get('launcher_reaped', False))}), every owned "
                        f"descriptor was closed, and the per-effect cgroup was removed ({removal}). "
                        "No completion and no export were recorded."
                    ),
                )
            return _command_start_failure(request, "cgroup_membership_unverified")

        process = supervised.process_observation
        export_error: str | None = None
        if (
            process.process_started
            and process.namespace_quiescent
            and not process.descendants_alive_at_direct_exit
            and not process.timed_out
            and not process.cancelled
            and process.status_document_present
            and process.exit_code is not None
        ):
            try:
                if private_view.source_mutated(binding.root_fd):
                    export_error = "source_mutated_during_effect"
                else:
                    change_set = compute_change_set(
                        baseline_fd=binding.root_fd,
                        private_fd=private_view.view_fd,
                    )
                    if durable_root is None:
                        raise PrivateWorkspaceError("export_durable_root_required", "missing")
                    _reservation, receipt, _reconciliation = apply_export(
                        source_root_fd=binding.root_fd,
                        private_fd=private_view.view_fd,
                        change_set=change_set,
                        reservation_id=f"export-{process.start_monotonic_ns}",
                        source_snapshot=private_view.source_snapshot,
                        view_identity=private_view.view_identity,
                        durable_root=durable_root,
                        causal=causal,
                    )
                    if receipt.state != "APPLIED":
                        export_error = receipt.refusal_code or receipt.state
            except PrivateWorkspaceError as error:
                export_error = error.code

        if not process.process_started:
            result = RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="FAILED",
                process_started=False,
                exit_code=None,
                error_code="executor_start_failure",
            )
        elif supervised.refused_non_utf8:
            result = RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="FAILED",
                process_started=True,
                stdout="",
                stderr="",
                exit_code=process.exit_code,
                error_code="non_utf8_output",
            )
        elif export_error is not None:
            result = RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="FAILED",
                process_started=True,
                stdout=supervised.stdout_text,
                stderr=supervised.stderr_text,
                stdout_truncated=supervised.stdout_observation.retained_truncated,
                stderr_truncated=supervised.stderr_observation.retained_truncated,
                exit_code=process.exit_code,
                error_code=f"trusted_export_{export_error}",
            )
        else:
            quiescent = process.namespace_quiescent and not process.descendants_alive_at_direct_exit
            outcome = (
                "OK"
                if (
                    process.exit_code is not None
                    and not process.timed_out
                    and not process.cancelled
                    and process.status_document_present
                    and quiescent
                )
                else "FAILED"
            )
            result = RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome=outcome,
                process_started=True,
                stdout=supervised.stdout_text,
                stderr=supervised.stderr_text,
                stdout_truncated=supervised.stdout_observation.retained_truncated,
                stderr_truncated=supervised.stderr_observation.retained_truncated,
                exit_code=process.exit_code,
                error_code=None if outcome == "OK" else _command_failure_code(process),
            )
        return _CommandExecution(
            result=result,
            process_observation=process,
            stdout_observation=supervised.stdout_observation,
            stderr_observation=supervised.stderr_observation,
            resource_observation=supervised.resource_observation,
            timed_out=process.timed_out,
            cancelled=process.cancelled,
        )
    finally:
        if runtime is not None:
            runtime.close()
        else:
            private_view.close()


def _command_start_failure(
    request: RunCommandRequest,
    error_code: str,
    *,
    execution_outcome_semantics: str | None = None,
) -> _CommandExecution:
    """A launch that failed after STARTED still owes process-domain observations.

    ``execution_outcome_semantics`` exists because a refusal around the trusted
    gate can leave the controller genuinely unable to say whether the launcher
    image ran (M2-B30).  ``ProcessObservation`` records the absence of an
    observed process outcome; this sentence records whether that absence means
    "nothing executed" or "the outcome is unknown", so the durable evidence
    never overstates the first.
    """

    from .canonical import Fingerprint
    from .observation import ProcessObservation, ResourceObservation, StreamObservation
    from .process_supervision import STREAM_FINGERPRINT_DOMAINS
    import hashlib

    now_wall = int(time.time() * 1000)
    now_mono = time.monotonic_ns()
    empty_fp = Fingerprint("sha256", STREAM_FINGERPRINT_DOMAINS["stdout"], hashlib.sha256(b"").hexdigest()).validated()
    empty_fp_err = Fingerprint("sha256", STREAM_FINGERPRINT_DOMAINS["stderr"], hashlib.sha256(b"").hexdigest()).validated()
    process = ProcessObservation.create(
        process_started=False,
        child_pid=None,
        child_process_group_id=None,
        exit_code=None,
        terminating_signal=None,
        timed_out=False,
        cancelled=False,
        start_wall_clock_unix_ms=now_wall,
        end_wall_clock_unix_ms=now_wall,
        start_monotonic_ns=now_mono,
        end_monotonic_ns=now_mono,
        duration_ns=0,
        termination_escalation=(),
        descendants_reaped=True,
        start_failure_class=error_code,
        capsule_mechanism="bubblewrap",
        launcher_exit_code=None,
        status_document_present=False,
        namespace_quiescent=True,
        descendants_alive_at_direct_exit=False,
        extra_descendants_reaped=0,
    )
    stdout = StreamObservation.create(
        stream_name="stdout",
        total_bytes=0,
        retained_bytes=0,
        retained_truncated=False,
        stream_fingerprint=empty_fp,
        text_decode_status="UTF8_DECODED",
    )
    stderr = StreamObservation.create(
        stream_name="stderr",
        total_bytes=0,
        retained_bytes=0,
        retained_truncated=False,
        stream_fingerprint=empty_fp_err,
        text_decode_status="UTF8_DECODED",
    )
    resource = ResourceObservation.create(
        child_cpu_user_ms=None,
        child_cpu_user_availability="NOT_MEASURED",
        child_cpu_system_ms=None,
        child_cpu_system_availability="NOT_MEASURED",
        child_max_rss_kib=None,
        child_max_rss_availability="NOT_MEASURED",
        controller_peak_retained_output_bytes=0,
        controller_peak_retained_availability="OBSERVED",
        measurement_semantics=(
            execution_outcome_semantics
            or "no process was started; containment was not observed"
        ),
        containment_mechanism="NONE",
        containment_availability="NOT_MEASURED",
        containment_bounds=(),
        containment_semantics=(
            execution_outcome_semantics
            or "no resource containment was recorded for this effect"
        ),
    )
    result = RunCommandResult.create(
        request_fingerprint=request.request_fingerprint,
        outcome="FAILED",
        process_started=False,
        exit_code=None,
        error_code=error_code,
    )
    return _CommandExecution(
        result=result,
        process_observation=process,
        stdout_observation=stdout,
        stderr_observation=stderr,
        resource_observation=resource,
        timed_out=False,
        cancelled=False,
    )


def _command_failure_code(process: ProcessObservation) -> str:
    if process.timed_out:
        return "command_timed_out"
    if process.cancelled:
        return "command_cancelled"
    if not process.status_document_present:
        return "process_domain_not_observed"
    if process.descendants_alive_at_direct_exit:
        return "descendant_outlived_the_direct_process"
    if not process.namespace_quiescent:
        return "process_domain_not_quiescent"
    return "command_terminated_by_signal"


# --- the shared executor -----------------------------------------------------

@dataclass(frozen=True)
class EffectExecutionOutcome:
    """Everything one execution of the shared substrate produced."""

    receipt: EffectReceipt
    reconciliation: EffectReconciliationReport
    publication_receipts: tuple[PublicationReceipt, ...]
    ledger_entry: EffectLedgerEntry | None
    tool_result: ToolResult | None
    reservation: EffectReservation | None
    effect_crossed_boundary: bool
    durable_at_effect_boundary: tuple[str, ...]


class TypedReconciliationRefused(Exception):
    """The durable chain did not reconcile, so no outcome may be claimed."""

    def __init__(self, final: FinalReconciliation) -> None:
        super().__init__(f"typed reconciliation refused: {final.refusal_code}")
        self.final = final


class ConfigurationRefused(Exception):
    """A configuration or identity error found *before* any effect was possible.

    Milestone 2 discovered mismatches such as a ledger belonging to a different
    run only when it tried to append in memory -- which happened after the
    effect had already executed and been published.  Every such check now runs
    during preflight, before the proposal is durable.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _index_outcome_for(receipt_status: str) -> str:
    return {
        "COMPLETED": "EFFECT_COMPLETED",
        "FAILED": "EFFECT_FAILED",
        "REFUSED": "EFFECT_REFUSED",
        "TIMED_OUT": "EFFECT_TIMED_OUT",
        "CANCELLED": "EFFECT_CANCELLED",
    }.get(receipt_status, "AMBIGUOUS_REQUIRES_RECONCILIATION")


class SharedEffectSubstrate:
    """The single physical execution object for both future conditions.

    ``execute`` is the only entry point.  It takes typed M1 objects and applies
    exactly one order: validate, publish the proposal, validate the decision,
    reserve, publish STARTED, and only then cross the local effect boundary.
    """

    def __init__(
        self,
        *,
        binding: WorkspaceBinding,
        store: DurableObjectStore,
        ledger: RunEffectLedger,
        injector: Any | None = None,
        effect_boundary_hook: Callable[[], None] | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._binding = binding
        self._store = store
        self._ledger = ledger
        self._injector = injector or store.injector or NULL_FAULT_INJECTOR
        self._effect_boundary_hook = effect_boundary_hook
        self._cancellation = cancellation
        self._run_index = DurableRunIndex(store, ledger.run_id)
        self.effect_invocation_count = 0

    @property
    def run_index(self) -> DurableRunIndex:
        return self._run_index

    def _index(
        self,
        *,
        event_kind: str,
        proposal: CanonicalProposal,
        decision: ModeDecision | None = None,
        outcome: str | None = None,
        effect_crossed_boundary: bool = False,
        effect_receipt_fingerprint: Fingerprint | None = None,
        ledger_entry_fingerprint: Fingerprint | None = None,
        final_reconciliation_fingerprint: Fingerprint | None = None,
        bind_capsule_identity: bool = False,
    ) -> None:
        """Record one transition in the run's durable causal order.

        Every transition is indexed as it happens rather than summarised once at
        the end.  That is what makes a crash classifiable: a process that dies
        between a durable final reconciliation and its index event leaves a
        proposal whose earlier events are all present, which recovery can close
        from durable bytes.  The previous one-entry-per-proposal design could not
        express that state at all, so the completed effect simply vanished from
        the run's order.
        """

        # A transition that is already durable is not appended again.  This is
        # what lets a resumed attempt on a partially indexed proposal reach the
        # ambiguity check below instead of colliding with its own earlier event:
        # the causal order already records this transition, and the chain forbids
        # recording it twice.
        if self._run_index.has_event(proposal.proposal_id, event_kind):
            return
        if outcome is not None and self._run_index.is_closed(proposal.proposal_id):
            # The proposal already has a terminal event.  A second one would
            # claim the run closed it twice.
            return

        manifest = None
        if bind_capsule_identity:
            manifest = self._binding.capsule_runtime_manifest.record_fingerprint
        self._run_index.append_event(
            event_kind=event_kind,
            condition_id=proposal.condition.condition_id,
            session_id=proposal.session_identity.session_id,
            turn_id=proposal.turn_id,
            proposal_id=proposal.proposal_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            decision_value=None if decision is None else decision.decision,
            decision_permits_effect=None if decision is None else decision.permits_effect,
            outcome=outcome,
            effect_crossed_boundary=effect_crossed_boundary,
            effect_receipt_fingerprint=effect_receipt_fingerprint,
            ledger_entry_fingerprint=ledger_entry_fingerprint,
            final_reconciliation_fingerprint=final_reconciliation_fingerprint,
            capsule_runtime_manifest_fingerprint=manifest,
        )

    def _publish_capsule_runtime_manifest(self) -> CapsuleRuntimeManifest:
        """Publish this run's capsule identity once, under the run's identity.

        The manifest is durable evidence of what the capsule was made of.  It is
        published per run rather than per proposal because it is a property of
        the substrate, not of any one effect; every ``EFFECT_STARTED`` index
        event binds its fingerprint, so each effect names the exact capsule that
        carried it.
        """

        manifest = self._binding.capsule_runtime_manifest
        self._store.publish_record(
            object_kind=CAPSULE_RUNTIME_MANIFEST_OBJECT_KIND,
            object_id=self._ledger.run_id,
            record=manifest,
        )
        return manifest

    def preflight(self, specification: ExperimentSpecification, proposal: CanonicalProposal) -> None:
        """Validate every configuration and identity before anything is durable.

        Each check below corresponds to a mismatch that Milestone 2 could only
        discover after the effect had run and been published.  Running them here
        means a misconfigured substrate refuses with no proposal, no reservation,
        no effect, and no evidence of an attempt it never should have made.
        """

        # The supported schema is a constant of this substrate, so the check is
        # against that constant.  The shipped check compared a field with itself
        # and could never fire.  It runs first because a specification this
        # substrate does not implement should be refused before anything else is
        # inspected on the strength of it.
        if specification.schema_version != SUPPORTED_SPECIFICATION_SCHEMA_VERSION:
            raise ConfigurationRefused(
                "SCHEMA_VERSION_MISMATCH",
                f"specification schema version {specification.schema_version} is not the supported "
                f"{SUPPORTED_SPECIFICATION_SCHEMA_VERSION}",
            )
        specification.validated()
        run_id = proposal.run_identity.run_id
        if self._ledger.run_id != run_id:
            raise ConfigurationRefused(
                "LEDGER_RUN_IDENTITY_MISMATCH",
                f"the ledger belongs to run {self._ledger.run_id}, not {run_id}",
            )
        if self._run_index.run_id != run_id:
            raise ConfigurationRefused(
                "RUN_INDEX_RUN_IDENTITY_MISMATCH", "the durable run index belongs to another run"
            )
        if specification.run_identity.run_id != run_id:
            raise ConfigurationRefused(
                "SPECIFICATION_RUN_IDENTITY_MISMATCH",
                "the specification names a different run than the proposal",
            )
        if self._binding.experiment_specification_fingerprint != specification.specification_fingerprint:
            raise ConfigurationRefused(
                "WORKSPACE_SPECIFICATION_BINDING_MISMATCH",
                "the workspace is bound to a different experiment specification",
            )
        if specification.effect_executor_identity != specification.effect_executor_identity.validated():
            raise ConfigurationRefused("EXECUTOR_IDENTITY_INVALID", "the executor identity is malformed")
        # The evidence root the store actually writes to must be the exact root
        # this binding proved disjoint from the workspace.
        if str(self._store.root) != self._binding.store_root_identity.path:
            raise ConfigurationRefused(
                "EVIDENCE_ROOT_IDENTITY_MISMATCH",
                "the durable store root is not the evidence root this workspace was bound against",
            )
        store_fd = os.open(self._store.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if not self._binding.store_root_identity.matches_descriptor(store_fd):
                raise ConfigurationRefused(
                    "EVIDENCE_ROOT_REPLACED",
                    "the durable store root no longer matches its recorded inode identity",
                )
        finally:
            os.close(store_fd)
        self._binding.recheck_root_identity()
        if proposal.tool_name not in TOOL_EFFECT_CLASSIFICATIONS:
            raise ConfigurationRefused("TOOL_CATALOG_MISMATCH", f"unknown tool {proposal.tool_name}")
        # The capsule must be ready now, not at the moment of the effect.
        try:
            self._binding.capsule_readiness.require()
        except SandboxUnavailable as error:
            raise ConfigurationRefused("SANDBOX_NOT_READY", str(error)) from error
        # The capsule's byte identity is re-derived here, before the proposal is
        # durable.  Readiness proved what the launcher, interpreter, init, and
        # seccomp program were at probe time; this proves they still are, so a
        # replacement between readiness and the effect refuses instead of being
        # silently recorded as the capsule that was probed.
        try:
            self._binding.recheck_capsule_runtime_identity()
        except CapsuleIdentityRefused as error:
            raise ConfigurationRefused("CAPSULE_RUNTIME_IDENTITY_REFUSED", str(error)) from error
        try:
            state = self._run_index.state()
        except RunIndexBroken as error:
            raise ConfigurationRefused("RUN_INDEX_BROKEN", str(error)) from error
        if state.state == "HEAD_UPDATE_PENDING":
            # A crash between an event's commit and the head update is a
            # bookkeeping gap over an already-durable event, so it is repaired
            # here rather than blocking the run.  Nothing is replayed.
            self._run_index.recover_head()
            state = self._run_index.state()
        # The in-memory ledger is not the authority on what this run has done.
        # A restarted process starts empty, so the complete history is derived
        # from the durable index and adopted; an in-memory ledger that
        # contradicts that history is a refusal, never something to overwrite.
        if state.events:
            try:
                # A proposal a crash left open is expected here: this is exactly
                # the path a restarted controller takes to *refuse* replaying it.
                # Every closed proposal is still verified in full.
                durable = RunEffectLedger.verify(
                    self._store,
                    run_id,
                    specification=specification,
                    index=self._run_index,
                    require_closed=False,
                )
            except (ObservationError, CorruptDurableObject, RunIndexBroken) as error:
                raise ConfigurationRefused("RUN_HISTORY_UNVERIFIABLE", str(error)) from error
            try:
                self._ledger.adopt(durable.entries)
            except ObservationError as error:
                raise ConfigurationRefused("LEDGER_CONTRADICTS_DURABLE_HISTORY", str(error)) from error
        elif self._ledger.entries:
            raise ConfigurationRefused(
                "LEDGER_CONTRADICTS_DURABLE_HISTORY",
                "the in-memory ledger records effects that the durable run index does not",
            )

    @property
    def store(self) -> DurableObjectStore:
        return self._store

    @property
    def ledger(self) -> RunEffectLedger:
        return self._ledger

    @property
    def binding(self) -> WorkspaceBinding:
        return self._binding

    # -- public entry point ---------------------------------------------------

    def execute(
        self,
        *,
        specification: ExperimentSpecification,
        proposal: CanonicalProposal,
        decision: ModeDecision,
        reservation_id: str,
        receipt_id: str,
    ) -> EffectExecutionOutcome:
        receipts: list[PublicationReceipt] = []

        # 0. every configuration and identity check happens here, before the
        # proposal is durable and therefore before any effect is possible.
        self.preflight(specification, proposal)

        # 1. validate the experiment specification and the workspace binding.
        specification.validated()
        self._binding.validate_for_specification(specification)
        # 2. validate the proposal for that exact specification.
        proposal.validate_for_specification(specification)

        # 3. durably publish the canonical proposal before anything else, and
        # index it immediately.  The proposal event is durable before any effect
        # is possible, so an effect can never exist outside the run's causal
        # order -- which is exactly what a crash between the effect and a
        # single end-of-proposal summary used to produce.
        self._injector.check(FAULT_BEFORE_PROPOSAL_PUBLICATION)
        self._publish_capsule_runtime_manifest()
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_PROPOSAL,
                object_id=proposal.proposal_id,
                record=proposal,
                fault_point=STAGE_PROPOSAL_PUBLICATION,
            )
        )
        self._index(event_kind="PROPOSAL_PUBLISHED", proposal=proposal)
        self._injector.check(FAULT_AFTER_PROPOSAL_PUBLICATION)

        # 4. validate the decision for that exact proposal.
        decision.validate_for_proposal(proposal)
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_DECISION, object_id=proposal.proposal_id, record=decision
            )
        )
        if decision.permits_effect:
            self._index(event_kind="DECISION_PUBLISHED", proposal=proposal, decision=decision)
        if not decision.permits_effect:
            return self._refuse_before_effect(
                specification=specification,
                proposal=proposal,
                decision=decision,
                receipt_id=receipt_id,
                receipts=receipts,
            )

        # Duplicate effect execution is forbidden.  Before reserving anything the
        # substrate re-reads the durable state of this exact proposal; if an
        # earlier attempt may already have crossed the boundary, or if a durable
        # object is corrupt, it fails closed instead of replaying.
        prior = reconcile_effect(
            self._store, run_id=proposal.run_identity.run_id, proposal_id=proposal.proposal_id
        )
        if prior.effect_may_have_occurred or prior.corrupt_objects:
            self._publish_recovery_report(proposal.proposal_id, prior)
            # The ambiguity is indexed, so the run's order records that this
            # proposal was attempted and closed without replay rather than
            # leaving it open forever.
            self._index(
                event_kind="EFFECT_AMBIGUOUS",
                proposal=proposal,
                decision=decision,
                outcome="AMBIGUOUS_REQUIRES_RECONCILIATION",
                effect_crossed_boundary=prior.effect_may_have_occurred,
            )
            raise AmbiguousEffectRefused(prior)

        # 5. construct and durably publish the exact reservation.
        self._injector.check(FAULT_BEFORE_RESERVATION_PUBLICATION)
        reservation = EffectReservation.for_decision(
            specification=specification,
            reservation_id=reservation_id,
            proposal=proposal,
            decision=decision,
        )
        reservation.validate_for_decision(specification, proposal, decision)
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_RESERVATION, object_id=proposal.proposal_id, record=reservation
            )
        )
        self._index(event_kind="RESERVATION_PUBLISHED", proposal=proposal, decision=decision)
        self._injector.check(FAULT_AFTER_RESERVATION_PUBLICATION)

        return self._execute_permitted_effect(
            specification=specification,
            proposal=proposal,
            decision=decision,
            reservation=reservation,
            receipt_id=receipt_id,
            receipts=receipts,
        )

    # -- the shared post-decision path ---------------------------------------

    def _execute_permitted_effect(
        self,
        *,
        specification: ExperimentSpecification,
        proposal: CanonicalProposal,
        decision: ModeDecision,
        reservation: EffectReservation,
        receipt_id: str,
        receipts: list[PublicationReceipt],
    ) -> EffectExecutionOutcome:
        """The identical implementation for DIRECT and GOVERNED ALLOW.

        Nothing below inspects the condition, the decision value, or any
        governance field.  The decision was already reduced to the single fact
        that an effect is permitted.
        """

        wall_start = int(time.time() * 1000)
        monotonic_start = time.monotonic_ns()

        # 5b. resolve and retain the physical handles BEFORE any STARTED record
        # exists.  A physical refusal here is genuinely pre-effect, so the
        # receipt, the lifecycle, the ledger, and reconciliation all agree that
        # nothing started; there is no STARTED record contradicting a REFUSED
        # receipt.
        preparation = prepare_effect(self._binding, proposal.tool_request)
        if preparation.refusal is not None:
            try:
                return self._refuse_after_reservation(
                    specification=specification,
                    proposal=proposal,
                    decision=decision,
                    reservation=reservation,
                    receipt_id=receipt_id,
                    receipts=receipts,
                    result=preparation.refusal,
                )
            finally:
                preparation.close()

        # 6. durably publish the pre-effect STARTED lifecycle record.
        self._injector.check(FAULT_BEFORE_STARTED_PUBLICATION)
        started = LifecycleRecord.create(
            kind="STARTED",
            run_id=proposal.run_identity.run_id,
            proposal_id=proposal.proposal_id,
            reservation_id=reservation.reservation_id,
            receipt_status=None,
            proposal_fingerprint=proposal.proposal_fingerprint,
            reservation_fingerprint=reservation.reservation_fingerprint,
            effect_classification=TOOL_EFFECT_CLASSIFICATIONS[proposal.tool_name],
            wall_clock_unix_ms=wall_start,
            monotonic_ns=monotonic_start,
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_LIFECYCLE_STARTED, object_id=proposal.proposal_id, record=started
            )
        )
        # The started event binds the exact capsule identity that is about to
        # carry this effect, so the run's order names which capsule ran what.
        self._index(
            event_kind="EFFECT_STARTED",
            proposal=proposal,
            decision=decision,
            bind_capsule_identity=True,
        )
        self._injector.check(FAULT_AFTER_STARTED_BEFORE_EFFECT)
        self._injector.check(FAULT_OBSERVER_FAILURE_AFTER_STARTED)

        filesystem_before = observe_filesystem(self._binding.root_fd, phase="BEFORE_EFFECT")
        git_before = observe_git(
            self._binding.physical_root, self._binding.root_fd, phase="BEFORE_EFFECT"
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_FILESYSTEM_BEFORE, object_id=proposal.proposal_id, record=filesystem_before
            )
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_GIT_BEFORE, object_id=proposal.proposal_id, record=git_before
            )
        )

        # 7. cross the local effect boundary.
        durable_at_boundary = self._durable_pre_effect_state(proposal.proposal_id)
        self._injector.check(FAULT_SANDBOX_SUPERVISOR_DEATH)
        try:
            execution = self._cross_effect_boundary(
                proposal.tool_request,
                preparation,
                causal={
                    "run_id": proposal.run_identity.run_id,
                    "session_id": proposal.session_identity.session_id,
                    "proposal_id": proposal.proposal_id,
                    "decision_id": decision.decision_fingerprint.value,
                    "reservation_id": reservation.reservation_id,
                    "effect_id": proposal.proposal_id,
                },
            )
        finally:
            preparation.close()

        # 8. observe the result, strictly after process-domain quiescence.
        self._injector.check(FAULT_AFTER_EFFECT_BEFORE_AFTER_OBSERVATIONS)
        filesystem_after = observe_filesystem(self._binding.root_fd, phase="AFTER_EFFECT")
        # Every AFTER observation happens strictly after process-domain
        # quiescence: supervise_command returns only once the launcher has been
        # reaped, and the launcher exits only after the in-capsule init saw
        # ECHILD.  No descendant can still be mutating the workspace here.
        git_after = observe_git(
            self._binding.physical_root, self._binding.root_fd, phase="AFTER_EFFECT"
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_FILESYSTEM_AFTER, object_id=proposal.proposal_id, record=filesystem_after
            )
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_GIT_AFTER, object_id=proposal.proposal_id, record=git_after
            )
        )
        process_observation = execution.process_observation
        stdout_observation = execution.stdout_observation
        stderr_observation = execution.stderr_observation
        resource_observation = execution.resource_observation
        for kind, record in (
            (OBJECT_KIND_PROCESS, process_observation),
            (OBJECT_KIND_STDOUT, stdout_observation),
            (OBJECT_KIND_STDERR, stderr_observation),
            (OBJECT_KIND_RESOURCE, resource_observation),
        ):
            if record is not None:
                receipts.append(
                    self._store.publish_record(object_kind=kind, object_id=proposal.proposal_id, record=record)
                )

        self._injector.check(FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT)

        # 9. construct and durably publish the terminal receipt.
        receipt = self._terminal_receipt(
            receipt_id=receipt_id,
            proposal=proposal,
            reservation=reservation,
            execution=execution,
        )
        receipt.validate_for_causal_chain(
            specification=specification, proposal=proposal, decision=decision, reservation=reservation
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_RECEIPT,
                object_id=proposal.proposal_id,
                record=receipt,
                fault_point=STAGE_TERMINAL_RECEIPT_PUBLICATION,
            )
        )
        self._index(
            event_kind="TERMINAL_RECEIPT_PUBLISHED",
            proposal=proposal,
            decision=decision,
            effect_crossed_boundary=True,
            effect_receipt_fingerprint=receipt.receipt_fingerprint,
        )
        monotonic_end = time.monotonic_ns()
        wall_end = int(time.time() * 1000)
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_LIFECYCLE_TERMINAL,
                object_id=proposal.proposal_id,
                record=LifecycleRecord.create(
                    kind="TERMINAL",
                    run_id=proposal.run_identity.run_id,
                    proposal_id=proposal.proposal_id,
                    reservation_id=reservation.reservation_id,
                    receipt_status=receipt.status,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    reservation_fingerprint=reservation.reservation_fingerprint,
                    effect_classification=receipt.effect_classification,
                    wall_clock_unix_ms=wall_end,
                    monotonic_ns=monotonic_end,
                ),
            )
        )
        self._injector.check(FAULT_AFTER_TERMINAL_RECEIPT_BEFORE_RECONCILIATION)

        # 10. publish reconciliation evidence and verify the ledger from bytes.
        entry = EffectLedgerEntry.create(
            experiment_specification_fingerprint=specification.specification_fingerprint,
            run_id=proposal.run_identity.run_id,
            condition_id=proposal.condition.condition_id,
            session_id=proposal.session_identity.session_id,
            proposal_id=proposal.proposal_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            decision_fingerprint=decision.decision_fingerprint,
            decision_value=decision.decision,
            reservation_id=reservation.reservation_id,
            reservation_fingerprint=reservation.reservation_fingerprint,
            lifecycle_receipt_fingerprints=(
                started.record_fingerprint.value,
                receipt.receipt_fingerprint.value,
            ),
            effect_receipt_fingerprint=receipt.receipt_fingerprint,
            tool_name=proposal.tool_name,
            effect_classification=receipt.effect_classification,
            tool_request_fingerprint=proposal.tool_request.request_fingerprint,
            tool_result_fingerprint=None if receipt.tool_result is None else receipt.tool_result.result_fingerprint,
            publication_receipt_fingerprints=tuple(item.record_fingerprint.value for item in receipts),
            wall_clock_start_unix_ms=wall_start,
            wall_clock_end_unix_ms=wall_end,
            monotonic_start_ns=monotonic_start,
            monotonic_end_ns=monotonic_end,
            filesystem_observation_before_fingerprint=filesystem_before.record_fingerprint,
            filesystem_observation_after_fingerprint=filesystem_after.record_fingerprint,
            git_observation_before_fingerprint=git_before.record_fingerprint,
            git_observation_after_fingerprint=git_after.record_fingerprint,
            process_observation_fingerprint=None if process_observation is None else process_observation.record_fingerprint,
            stdout_observation_fingerprint=None if stdout_observation is None else stdout_observation.record_fingerprint,
            stderr_observation_fingerprint=None if stderr_observation is None else stderr_observation.record_fingerprint,
            resource_observation_fingerprint=None if resource_observation is None else resource_observation.record_fingerprint,
            effect_crossed_boundary=True,
            # A ledger entry never asserts its own reconciliation.  The separate
            # FinalReconciliation record below is the only place a verified
            # verdict may appear, and it is written only after verification.
            final_reconciliation_state=LEDGER_PENDING_STATE,
        )
        self._store.publish_record(
            object_kind=LEDGER_OBJECT_KIND,
            object_id=proposal.proposal_id,
            record=entry,
            fault_point=STAGE_LEDGER_PENDING_PUBLICATION,
        )
        reconciliation = reconcile_effect(
            self._store, run_id=proposal.run_identity.run_id, proposal_id=proposal.proposal_id
        )
        self._store.publish_record(
            object_kind=OBJECT_KIND_RECONCILIATION,
            object_id=proposal.proposal_id,
            record=reconciliation,
            fault_point=STAGE_RECONCILIATION_PUBLICATION,
        )

        # 11. reconcile the complete typed chain from durable bytes and publish
        # the separate final record.  This is the authoritative verdict; the
        # ledger entry above only stated what happened.
        final = reconcile_typed_chain(
            self._store,
            run_id=proposal.run_identity.run_id,
            proposal_id=proposal.proposal_id,
            specification=specification,
        )
        self._injector.check(FAULT_BEFORE_FINAL_RECONCILIATION)
        self._store.publish_record(
            object_kind=FINAL_RECONCILIATION_OBJECT_KIND,
            object_id=proposal.proposal_id,
            record=final,
            fault_point=STAGE_FINAL_RECONCILIATION_PUBLICATION,
        )
        if not final.verified:
            raise TypedReconciliationRefused(final)

        # 12. close the proposal in the durable order.  This event is what makes
        # the window between a durable final reconciliation and the run's order
        # recoverable: every earlier transition is already indexed, so recovery
        # can append exactly this event from durable bytes without replaying.
        self._index(
            event_kind="RECONCILIATION_PUBLISHED",
            proposal=proposal,
            decision=decision,
            outcome=_index_outcome_for(receipt.status),
            effect_crossed_boundary=True,
            effect_receipt_fingerprint=receipt.receipt_fingerprint,
            ledger_entry_fingerprint=entry.record_fingerprint,
            final_reconciliation_fingerprint=final.record_fingerprint,
        )

        # 13. verify the ledger against the *durable index*, not against a list
        # of proposal identities the caller chose.  The history being checked is
        # therefore the run's whole history, including everything a restarted
        # process has no memory of.
        verified = RunEffectLedger.verify(
            self._store,
            proposal.run_identity.run_id,
            specification=specification,
            index=self._run_index,
        )
        self._ledger.adopt(verified.entries)

        return EffectExecutionOutcome(
            receipt=receipt,
            reconciliation=reconciliation,
            publication_receipts=tuple(receipts),
            ledger_entry=verified.entries[-1],
            tool_result=receipt.tool_result,
            reservation=reservation,
            effect_crossed_boundary=True,
            durable_at_effect_boundary=durable_at_boundary,
        )

    # -- the physical effect boundary ----------------------------------------

    def _cross_effect_boundary(
        self,
        request: ToolRequest,
        preparation: "_EffectPreparation",
        *,
        causal: dict[str, str] | None = None,
    ) -> _CommandExecution:
        """The single point at which this process touches the workspace."""

        if self._effect_boundary_hook is not None:
            self._effect_boundary_hook()
        self.effect_invocation_count += 1
        if isinstance(request, ListFilesRequest):
            result: ToolResult = _list_files(self._binding, request, preparation)
        elif isinstance(request, ReadFileRequest):
            result = _read_file(self._binding, request, preparation)
        elif isinstance(request, WriteFileRequest):
            result = _write_file(self._binding, request, preparation)
        elif isinstance(request, RunCommandRequest):
            return _run_command(
                self._binding,
                request,
                preparation=preparation,
                cancellation=self._cancellation,
                start_hook=None,
                durable_root=self._store.root,
                causal=causal,
            )
        else:  # pragma: no cover - the typed union is closed
            raise TypeError("unknown typed tool request")
        return _CommandExecution(
            result=result,
            process_observation=None,
            stdout_observation=None,
            stderr_observation=None,
            resource_observation=None,
            timed_out=False,
            cancelled=False,
        )

    # -- receipts -------------------------------------------------------------

    def _terminal_receipt(
        self,
        *,
        receipt_id: str,
        proposal: CanonicalProposal,
        reservation: EffectReservation,
        execution: _CommandExecution,
    ) -> EffectReceipt:
        result = execution.result
        if execution.timed_out:
            return EffectReceipt.for_proposal(
                receipt_id=receipt_id,
                proposal=proposal,
                status="TIMED_OUT",
                reservation=reservation,
                execution_failure="RESULT_NOT_PRODUCED",
                outcome_reason="the command exceeded its request timeout and its process group was terminated",
            )
        if execution.cancelled:
            return EffectReceipt.for_proposal(
                receipt_id=receipt_id,
                proposal=proposal,
                status="CANCELLED",
                reservation=reservation,
                execution_failure="RESULT_NOT_PRODUCED",
                outcome_reason="the effect was cancelled and its process group was terminated",
            )
        if result.outcome == "REFUSED":
            return EffectReceipt.for_proposal(
                receipt_id=receipt_id,
                proposal=proposal,
                status="REFUSED",
                reservation=reservation,
                tool_result=result,
                outcome_reason=f"the workspace binding refused the request: {result.error_code}",
            )
        exit_code = getattr(result, "exit_code", None)
        if result.outcome == "FAILED":
            return EffectReceipt.for_proposal(
                receipt_id=receipt_id,
                proposal=proposal,
                status="FAILED",
                reservation=reservation,
                tool_result=result,
                process_exit_code=exit_code,
                outcome_reason=f"the effect failed: {result.error_code}",
            )
        return EffectReceipt.for_proposal(
            receipt_id=receipt_id,
            proposal=proposal,
            status="COMPLETED",
            reservation=reservation,
            tool_result=result,
            process_exit_code=exit_code,
            outcome_reason="the tool executed the exact request; this is not a task acceptance",
        )

    def _refuse_before_effect(
        self,
        *,
        specification: ExperimentSpecification,
        proposal: CanonicalProposal,
        decision: ModeDecision,
        receipt_id: str,
        receipts: list[PublicationReceipt],
    ) -> EffectExecutionOutcome:
        receipt = EffectReceipt.for_proposal(
            receipt_id=receipt_id,
            proposal=proposal,
            status="REFUSED",
            outcome_reason=f"the mode decision {decision.decision} does not permit an effect",
        )
        receipt.validate_for_causal_chain(
            specification=specification, proposal=proposal, decision=decision, reservation=None
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_RECEIPT, object_id=proposal.proposal_id, record=receipt
            )
        )
        reconciliation = EffectReconciliationReport.create(
            run_id=proposal.run_identity.run_id,
            proposal_id=proposal.proposal_id,
            classification="PROPOSAL_ONLY_NO_EFFECT_POSSIBLE",
            effect_may_have_occurred=False,
            replay_permitted=False,
            durable_objects_present=tuple(sorted({OBJECT_KIND_PROPOSAL, OBJECT_KIND_DECISION, OBJECT_KIND_RECEIPT})),
            durable_objects_absent=(OBJECT_KIND_LIFECYCLE_STARTED, OBJECT_KIND_RESERVATION),
            partial_publications=self._store.partial_publications(),
            corrupt_objects=(),
            reconciliation_note="the decision refused the proposal, so no reservation and no effect exist",
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_RECONCILIATION, object_id=proposal.proposal_id, record=reconciliation
            )
        )
        # A refused proposal is a proposal the run attempted, so it is indexed
        # with the same care as one that produced an effect.
        self._index(
            event_kind="DECISION_REFUSED",
            proposal=proposal,
            decision=decision,
            outcome="DECISION_REFUSED",
            effect_receipt_fingerprint=receipt.receipt_fingerprint,
        )
        return EffectExecutionOutcome(
            receipt=receipt,
            reconciliation=reconciliation,
            publication_receipts=tuple(receipts),
            ledger_entry=None,
            tool_result=None,
            reservation=None,
            effect_crossed_boundary=False,
            durable_at_effect_boundary=(),
        )

    def _refuse_after_reservation(
        self,
        *,
        specification: ExperimentSpecification,
        proposal: CanonicalProposal,
        decision: ModeDecision,
        reservation: EffectReservation,
        receipt_id: str,
        receipts: list[PublicationReceipt],
        result: ToolResult,
    ) -> EffectExecutionOutcome:
        """A physical refusal proven before STARTED, so nothing ever started."""

        receipt = EffectReceipt.for_proposal(
            receipt_id=receipt_id,
            proposal=proposal,
            status="REFUSED",
            reservation=reservation,
            tool_result=result,
            outcome_reason=(
                "the physical preconditions were refused before the effect boundary was crossed: "
                f"{getattr(result, 'error_code', 'unknown')}"
            ),
        )
        receipt.validate_for_causal_chain(
            specification=specification, proposal=proposal, decision=decision, reservation=reservation
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_RECEIPT, object_id=proposal.proposal_id, record=receipt
            )
        )
        reconciliation = reconcile_effect(
            self._store, run_id=proposal.run_identity.run_id, proposal_id=proposal.proposal_id
        )
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_RECONCILIATION, object_id=proposal.proposal_id, record=reconciliation
            )
        )
        final = reconcile_typed_chain(
            self._store,
            run_id=proposal.run_identity.run_id,
            proposal_id=proposal.proposal_id,
            specification=specification,
        )
        self._store.publish_record(
            object_kind=FINAL_RECONCILIATION_OBJECT_KIND, object_id=proposal.proposal_id, record=final
        )
        if not final.verified:
            raise TypedReconciliationRefused(final)
        self._index(
            event_kind="EFFECT_REFUSED_BEFORE_START",
            proposal=proposal,
            decision=decision,
            outcome="EFFECT_REFUSED",
            effect_receipt_fingerprint=receipt.receipt_fingerprint,
        )
        return EffectExecutionOutcome(
            receipt=receipt,
            reconciliation=reconciliation,
            publication_receipts=tuple(receipts),
            ledger_entry=None,
            tool_result=result,
            reservation=reservation,
            effect_crossed_boundary=False,
            durable_at_effect_boundary=(),
        )

    def _publish_recovery_report(self, proposal_id: str, report: EffectReconciliationReport) -> None:
        try:
            self._store.publish_record(
                object_kind=OBJECT_KIND_RECONCILIATION,
                object_id=f"{proposal_id}-recovery",
                record=report,
            )
        except Exception:  # noqa: BLE001 - the refusal, not the report, is authoritative
            pass

    def _durable_pre_effect_state(self, proposal_id: str) -> tuple[str, ...]:
        """Read back, from the filesystem, what is durable at this instant."""

        present = []
        for kind in PRE_EFFECT_OBJECT_KINDS:
            if self._store.inspect(kind, proposal_id).durable:
                present.append(kind)
        return tuple(sorted(present))


# --- crash-safe reconciliation ----------------------------------------------

_RECONCILIATION_ORDER = (
    OBJECT_KIND_PROPOSAL,
    OBJECT_KIND_RESERVATION,
    OBJECT_KIND_LIFECYCLE_STARTED,
    OBJECT_KIND_RECEIPT,
    LEDGER_OBJECT_KIND,
)


def reconcile_effect(store: DurableObjectStore, *, run_id: str, proposal_id: str) -> EffectReconciliationReport:
    """Classify one effect using only the bytes that are physically durable.

    Nothing in memory is consulted.  The classification never permits automatic
    replay once an effect may have occurred, and a corrupt committed object
    fails closed instead of being interpreted.
    """

    present: list[str] = []
    absent: list[str] = []
    corrupt: list[str] = []
    for kind in _RECONCILIATION_ORDER:
        receipt = store.inspect(kind, proposal_id)
        if receipt.state == "CORRUPT":
            corrupt.append(kind)
        elif receipt.durable:
            present.append(kind)
        else:
            absent.append(kind)

    partial = store.partial_publications()
    effect_classification: str | None = None
    if OBJECT_KIND_PROPOSAL in present and not corrupt:
        try:
            payload = store.load(OBJECT_KIND_PROPOSAL, proposal_id)
            effect_classification = TOOL_EFFECT_CLASSIFICATIONS[payload["tool_name"]]
        except Exception:  # noqa: BLE001 - any failure here is a corrupt object
            corrupt.append(OBJECT_KIND_PROPOSAL)

    if corrupt:
        classification = "FAILED_CLOSED_CORRUPT_DURABLE_OBJECT"
        may_have_occurred = OBJECT_KIND_LIFECYCLE_STARTED in present
        note = "a committed durable object could not be reconstructed; the effect fails closed"
    elif OBJECT_KIND_PROPOSAL not in present:
        classification = "NO_DURABLE_STATE"
        may_have_occurred = False
        note = "no proposal is durable, so no effect can have been started by this substrate"
    elif OBJECT_KIND_RESERVATION not in present:
        classification = "PROPOSAL_ONLY_NO_EFFECT_POSSIBLE"
        may_have_occurred = False
        note = "the proposal is durable but no reservation exists, so no effect boundary was crossed"
    elif OBJECT_KIND_LIFECYCLE_STARTED not in present:
        classification = "RESERVED_NO_EFFECT_POSSIBLE"
        may_have_occurred = False
        note = "a reservation exists but no durable STARTED record, so no effect boundary was crossed"
    elif OBJECT_KIND_RECEIPT not in present:
        if effect_classification == "READ_ONLY":
            classification = "STARTED_AMBIGUOUS_READ_ONLY"
            note = "a read-only effect started and produced no terminal receipt; its state is ambiguous"
        else:
            classification = "STARTED_AMBIGUOUS_EFFECT_REQUIRES_RECONCILIATION"
            note = "a mutating effect started and produced no terminal receipt; it requires reconciliation"
        may_have_occurred = True
    elif LEDGER_OBJECT_KIND not in present:
        classification = "TERMINAL_RECEIPT_DURABLE_RECONCILIATION_INCOMPLETE"
        may_have_occurred = True
        note = "the terminal receipt is durable but the ledger entry is not; reconciliation is incomplete"
    else:
        classification = "RECONCILED_COMPLETE"
        may_have_occurred = True
        note = "every durable object for this effect is present and reconstructible"

    return EffectReconciliationReport.create(
        run_id=run_id,
        proposal_id=proposal_id,
        classification=classification,
        effect_may_have_occurred=may_have_occurred,
        # Duplicate effect execution is forbidden: once an effect may have
        # occurred the substrate never replays it automatically.
        replay_permitted=False,
        durable_objects_present=tuple(sorted(set(present))),
        durable_objects_absent=tuple(sorted(set(absent))),
        partial_publications=tuple(sorted(set(partial))),
        corrupt_objects=tuple(sorted(set(corrupt))),
        reconciliation_note=note,
    )


# --- run-index recovery ------------------------------------------------------

#: The durable object each transition is indexed against, in the exact order the
#: substrate produces them.  Recovery walks this list and appends only the events
#: whose objects are already durable, so the recovered event set is exactly the
#: one the normal path would have written.
_RECOVERY_STEPS: tuple[tuple[str, str], ...] = (
    (OBJECT_KIND_DECISION, "DECISION_PUBLISHED"),
    (OBJECT_KIND_RESERVATION, "RESERVATION_PUBLISHED"),
    (OBJECT_KIND_LIFECYCLE_STARTED, "EFFECT_STARTED"),
    (OBJECT_KIND_RECEIPT, "TERMINAL_RECEIPT_PUBLISHED"),
    (FINAL_RECONCILIATION_OBJECT_KIND, "RECONCILIATION_PUBLISHED"),
)

#: Transitions a refusing decision never produces, so recovery never invents them.
_EFFECT_ONLY_EVENTS = frozenset({"DECISION_PUBLISHED", "RESERVATION_PUBLISHED", "EFFECT_STARTED", "TERMINAL_RECEIPT_PUBLISHED"})


@dataclass(frozen=True)
class RunIndexRecovery:
    """What a recovery pass found and what it appended, if anything."""

    index_state: str
    appended_events: tuple[str, ...]
    still_open_proposal_ids: tuple[str, ...]
    replayed_any_effect: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_state": self.index_state,
            "appended_events": list(self.appended_events),
            "still_open_proposal_ids": list(self.still_open_proposal_ids),
            "replayed_any_effect": self.replayed_any_effect,
        }


def recover_run_index(store: DurableObjectStore, run_id: str) -> RunIndexRecovery:
    """Close index events whose durable objects already exist.  Never replay.

    The failure this exists for is exact: a process that dies after publishing a
    verified final reconciliation but before appending the event that records it
    leaves a real, completed, fully reconciled effect that the run's causal order
    does not mention.  Recovery reads the durable objects, works out which of the
    proposal's transitions were never indexed, and appends exactly those.

    It writes no proposal, no reservation, no lifecycle record, no receipt, and
    no reconciliation.  It cannot cause an effect: every event it appends
    describes an object that was already on disk before this function was
    called.
    """

    index = DurableRunIndex(store, run_id)
    state = index.state()
    if state.state == "HEAD_UPDATE_PENDING":
        index.recover_head()
        state = index.state()

    appended: list[str] = []
    for proposal_id in index.open_proposal_ids():
        events = {event.event_kind for event in index.events_for(proposal_id)}
        proposal_payload = store.load(OBJECT_KIND_PROPOSAL, proposal_id)
        proposal = CanonicalProposal.from_dict(proposal_payload)
        decision_state = store.inspect(OBJECT_KIND_DECISION, proposal_id)
        if decision_state.state != "PUBLISHED":
            # Without a durable decision nothing further can be asserted about
            # this proposal, and inventing one would be a fabrication.
            continue
        decision = ModeDecision.from_dict(store.load(OBJECT_KIND_DECISION, proposal_id))

        # An effect crossed the boundary exactly when a STARTED record is durable.
        started = store.inspect(OBJECT_KIND_LIFECYCLE_STARTED, proposal_id).state == "PUBLISHED"
        receipt_fingerprint = (
            EffectReceipt.from_dict(store.load(OBJECT_KIND_RECEIPT, proposal_id)).receipt_fingerprint
            if store.inspect(OBJECT_KIND_RECEIPT, proposal_id).state == "PUBLISHED"
            else None
        )

        for object_kind, event_kind in _RECOVERY_STEPS:
            if not decision.permits_effect and event_kind in _EFFECT_ONLY_EVENTS:
                continue
            if store.inspect(object_kind, proposal_id).state != "PUBLISHED":
                # The transitions are ordered, so the first absent object is
                # where this proposal actually stopped.
                break
            if event_kind in events:
                continue

            if event_kind != "RECONCILIATION_PUBLISHED":
                index.append_event(
                    event_kind=event_kind,
                    condition_id=proposal.condition.condition_id,
                    session_id=proposal.session_identity.session_id,
                    turn_id=proposal.turn_id,
                    proposal_id=proposal_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    decision_value=decision.decision,
                    decision_permits_effect=decision.permits_effect,
                    effect_crossed_boundary=started and event_kind == "TERMINAL_RECEIPT_PUBLISHED",
                    effect_receipt_fingerprint=receipt_fingerprint,
                )
                appended.append(f"{proposal_id}:{event_kind}")
                continue

            final = FinalReconciliation.from_dict(
                store.load(FINAL_RECONCILIATION_OBJECT_KIND, proposal_id)
            )
            if not final.verified:
                # An unverified reconciliation closes nothing; the proposal stays
                # open and a human decides what happened.
                break
            closing = _closing_event_kind(decision, started=started)
            index.append_event(
                event_kind=closing,
                condition_id=proposal.condition.condition_id,
                session_id=proposal.session_identity.session_id,
                turn_id=proposal.turn_id,
                proposal_id=proposal_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                decision_value=decision.decision,
                decision_permits_effect=decision.permits_effect,
                outcome=(
                    _index_outcome_for(final.receipt_status)
                    if closing == "RECONCILIATION_PUBLISHED"
                    else ("EFFECT_REFUSED" if decision.permits_effect else "DECISION_REFUSED")
                ),
                effect_crossed_boundary=started,
                effect_receipt_fingerprint=receipt_fingerprint,
                ledger_entry_fingerprint=(
                    EffectLedgerEntry.from_dict(
                        store.load(LEDGER_OBJECT_KIND, proposal_id)
                    ).record_fingerprint
                    if started
                    else None
                ),
                final_reconciliation_fingerprint=final.record_fingerprint,
            )
            appended.append(f"{proposal_id}:{closing}")

    return RunIndexRecovery(
        index_state=index.state().state,
        appended_events=tuple(appended),
        still_open_proposal_ids=index.open_proposal_ids(),
        replayed_any_effect=False,
    )


def _closing_event_kind(decision: ModeDecision, *, started: bool) -> str:
    """The terminal event the normal path would have written for this proposal."""

    if not decision.permits_effect:
        return "DECISION_REFUSED"
    return "RECONCILIATION_PUBLISHED" if started else "EFFECT_REFUSED_BEFORE_START"


def workspace_content_digest(root: Path) -> str:
    """A convenience digest used by tests to prove exact written bytes."""

    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            digest.update(str(path.relative_to(root)).encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


__all__ = [
    "AmbiguousEffectRefused",
    "ConfigurationRefused",
    "EffectExecutionOutcome",
    "EvidenceRootIsolationError",
    "OBJECT_KIND_DECISION",
    "OBJECT_KIND_LIFECYCLE_STARTED",
    "OBJECT_KIND_PROPOSAL",
    "OBJECT_KIND_RECEIPT",
    "OBJECT_KIND_RECONCILIATION",
    "OBJECT_KIND_RESERVATION",
    "PRE_EFFECT_OBJECT_KINDS",
    "SANITIZED_ENVIRONMENT_BASE",
    "SUPPORTED_SPECIFICATION_SCHEMA_VERSION",
    "RunIndexRecovery",
    "SharedEffectSubstrate",
    "TypedReconciliationRefused",
    "WorkspaceBinding",
    "WorkspaceFailure",
    "WorkspaceIpcEndpointRefused",
    "WorkspaceRefusal",
    "observe_filesystem",
    "observe_git",
    "recover_run_index",
    "reconcile_effect",
    "require_no_workspace_ipc_endpoints",
    "scan_workspace_ipc_endpoints",
    "stable_identity",
    "workspace_content_digest",
]
