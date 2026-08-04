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
    FAULT_AFTER_EFFECT_BEFORE_TERMINAL_RECEIPT,
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
    DurableObjectStore,
    NULL_FAULT_INJECTOR,
)
from .effect_ledger import LEDGER_OBJECT_KIND, EffectLedgerEntry, RunEffectLedger
from .identities import IdentityReference
from .observation import (
    SCHEMA_FILESYSTEM_OBSERVATION,
    SCHEMA_GIT_OBSERVATION,
    EffectReconciliationReport,
    FilesystemObservation,
    GitObservation,
    LifecycleRecord,
    ProcessObservation,
    PublicationReceipt,
    ResourceObservation,
    StreamObservation,
)
from .process_supervision import CancellationToken, supervise_command
from .schemas import TOOL_EFFECT_CLASSIFICATIONS
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
GIT_OBSERVATION_TIMEOUT_SECONDS = 20.0
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

def observe_filesystem(root_fd: int, *, phase: str) -> FilesystemObservation:
    """Fingerprint the workspace tree without following any symlink."""

    entries: list[dict[str, Any]] = []
    total_bytes = 0
    truncated = False
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
                if stat.S_ISDIR(info.st_mode):
                    kind = "directory"
                    size = 0
                elif stat.S_ISLNK(info.st_mode):
                    kind = "symlink"
                    size = info.st_size
                elif stat.S_ISREG(info.st_mode):
                    kind = "regular_file"
                    size = info.st_size
                    total_bytes += size
                else:
                    kind = "other"
                    size = 0
                if len(entries) >= MAX_OBSERVED_TREE_ENTRIES:
                    truncated = True
                    continue
                entries.append(
                    {
                        "path": relative,
                        "kind": kind,
                        "size": size if kind == "regular_file" else 0,
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                if kind == "directory":
                    try:
                        child = _open_child_directory(directory_fd, name)
                    except (WorkspaceRefusal, WorkspaceFailure):  # pragma: no cover
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
    return FilesystemObservation.create(
        phase=phase,
        entry_count=len(entries),
        total_regular_file_bytes=total_bytes,
        truncated=truncated,
        tree_fingerprint=fingerprint({"entries": entries}, domain=TREE_FINGERPRINT_DOMAIN),
        availability="OBSERVED",
    )


def observe_git(root: Path, *, phase: str) -> GitObservation:
    """Observe Git HEAD, index, and worktree state when Git is usable."""

    if not (root / ".git").exists():
        return GitObservation.create(phase=phase, availability="REPOSITORY_ABSENT", repository_present=False)
    git = shutil.which("git", path=SANITIZED_ENVIRONMENT_BASE["PATH"]) or shutil.which("git")
    if git is None:
        return GitObservation.create(
            phase=phase, availability="GIT_EXECUTABLE_UNAVAILABLE", repository_present=True
        )
    environment = dict(SANITIZED_ENVIRONMENT_BASE)
    environment["HOME"] = str(root)
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_CONFIG_SYSTEM"] = "/dev/null"
    environment["GIT_TERMINAL_PROMPT"] = "0"

    def run(arguments: list[str]) -> str | None:
        try:
            completed = subprocess.run(  # noqa: S603 - explicit argv, no shell
                [git, *arguments],
                cwd=str(root),
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=GIT_OBSERVATION_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if completed.returncode != 0:
            return None
        try:
            return completed.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None

    head = run(["rev-parse", "HEAD"])
    status = run(["status", "--porcelain=v1", "--untracked-files=all"])
    if head is None or status is None:
        return GitObservation.create(phase=phase, availability="GIT_COMMAND_FAILED", repository_present=True)
    lines = [line for line in status.splitlines() if line]
    return GitObservation.create(
        phase=phase,
        availability="OBSERVED",
        repository_present=True,
        head_commit=head.strip(),
        index_dirty=any(line[0] not in {" ", "?"} for line in lines),
        worktree_dirty=any(len(line) > 1 and line[1] not in {" ", "?"} for line in lines),
        untracked_present=any(line.startswith("??") for line in lines),
        status_fingerprint=fingerprint(
            {"head": head.strip(), "status": sorted(lines)}, domain=GIT_STATUS_FINGERPRINT_DOMAIN
        ),
    )


# --- workspace binding -------------------------------------------------------

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

    @classmethod
    def bind(cls, root: str | os.PathLike[str], specification: ExperimentSpecification) -> "WorkspaceBinding":
        specification.validated()
        physical = Path(root)
        if not physical.is_absolute():
            raise ValueError("the workspace root must be an absolute physical path")
        if physical.is_symlink():
            raise ValueError("the workspace root itself must not be a symlink")
        canonical = Path(os.path.realpath(physical))
        if canonical != physical:
            raise ValueError("the workspace root must equal its canonical resolved path")
        root_fd = os.open(physical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISDIR(os.fstat(root_fd).st_mode):  # pragma: no cover - O_DIRECTORY guarantees it
                raise ValueError("the workspace root must be a directory")
            filesystem = observe_filesystem(root_fd, phase="INITIAL")
            git = observe_git(physical, phase="INITIAL")
            return cls(
                physical_root=physical,
                canonical_root=canonical,
                working_root_identity=specification.working_root_identity,
                scope_identity=specification.scope_identity,
                experiment_specification_fingerprint=specification.specification_fingerprint,
                initial_filesystem_observation=filesystem,
                git_present=git.repository_present,
                initial_git_observation=git,
                root_fd=root_fd,
            )
        except BaseException:
            os.close(root_fd)
            raise

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

def _list_files(binding: WorkspaceBinding, request: ListFilesRequest) -> ListFilesResult:
    parts, leaf = _split_relative(request.path)
    descend = parts if leaf is None else parts + (leaf,)
    chain = binding.chain()
    collected: list[str] = []
    over_limit = False
    try:
        base_fd = chain.descend(descend)
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
        finally:
            for directory_fd, _, owned in stack:
                if owned:
                    try:
                        os.close(directory_fd)
                    except OSError:  # pragma: no cover
                        pass
    except WorkspaceRefusal as refusal:
        return ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, outcome="REFUSED", error_code=refusal.error_code
        )
    except WorkspaceFailure as failure:
        return ListFilesResult.create(
            request_fingerprint=request.request_fingerprint, outcome="FAILED", error_code=failure.error_code
        )
    finally:
        chain.close()

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


def _read_file(binding: WorkspaceBinding, request: ReadFileRequest) -> ReadFileResult:
    parts, leaf = _split_relative(request.path)
    if leaf is None:
        return ReadFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="REFUSED", error_code="path_is_directory"
        )
    chain = binding.chain()
    handle = -1
    try:
        parent_fd = chain.descend(parts)
        try:
            handle = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.EMLINK}:
                raise WorkspaceRefusal("final_path_is_symlink") from error
            if error.errno == errno.ENOENT:
                raise WorkspaceRefusal("path_absent") from error
            if error.errno == errno.EISDIR:
                raise WorkspaceRefusal("path_is_directory") from error
            if error.errno == errno.EACCES:
                raise WorkspaceRefusal("path_not_readable") from error
            raise WorkspaceFailure("file_open_failed") from error
        if stat.S_ISDIR(os.fstat(handle).st_mode):
            raise WorkspaceRefusal("path_is_directory")
        raw = b""
        while len(raw) <= MAX_CONTENT_BYTES:
            chunk = os.read(handle, 1 << 20)
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
    finally:
        if handle >= 0:
            os.close(handle)
        chain.close()

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


def _write_file(binding: WorkspaceBinding, request: WriteFileRequest) -> WriteFileResult:
    parts, leaf = _split_relative(request.path)
    if leaf is None:
        return WriteFileResult.create(
            request_fingerprint=request.request_fingerprint, outcome="REFUSED", error_code="path_is_directory"
        )
    payload = request.content.encode("utf-8", "strict")
    chain = binding.chain()
    temporary: str | None = None
    parent_fd = -1
    try:
        try:
            parent_fd = chain.descend(parts, create=request.create_parents)
        except WorkspaceRefusal as refusal:
            if refusal.error_code == "path_component_absent" and not request.create_parents:
                raise WorkspaceRefusal("parent_directory_absent") from refusal
            raise
        try:
            existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError as error:
            raise WorkspaceFailure("target_stat_failed") from error
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise WorkspaceRefusal("final_path_is_symlink")
            if stat.S_ISDIR(existing.st_mode):
                raise WorkspaceRefusal("path_is_directory")
            if not stat.S_ISREG(existing.st_mode):
                raise WorkspaceRefusal("path_is_not_a_regular_file")

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
        # never writes through a symlink, so the pre-check above is a refusal
        # policy rather than the safety mechanism.
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
        chain.close()

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
    cancellation: CancellationToken | None,
    start_hook: Callable[[], None] | None,
) -> _CommandExecution:
    parts, leaf = _split_relative(request.cwd)
    descend = parts if leaf is None else parts + (leaf,)
    chain = binding.chain()
    try:
        chain.descend(descend)
        physical_cwd = binding.physical_path_of(request.cwd)
        if Path(os.path.realpath(physical_cwd)) != physical_cwd:
            raise WorkspaceRefusal("cwd_is_not_physically_under_the_root")
    except WorkspaceRefusal as refusal:
        return _CommandExecution(
            result=RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="REFUSED",
                process_started=False,
                exit_code=None,
                error_code=refusal.error_code,
            ),
            process_observation=None,
            stdout_observation=None,
            stderr_observation=None,
            resource_observation=None,
            timed_out=False,
            cancelled=False,
        )
    except WorkspaceFailure as failure:
        return _CommandExecution(
            result=RunCommandResult.create(
                request_fingerprint=request.request_fingerprint,
                outcome="FAILED",
                process_started=False,
                exit_code=None,
                error_code=failure.error_code,
            ),
            process_observation=None,
            stdout_observation=None,
            stderr_observation=None,
            resource_observation=None,
            timed_out=False,
            cancelled=False,
        )
    finally:
        chain.close()

    environment = dict(SANITIZED_ENVIRONMENT_BASE)
    environment["HOME"] = str(binding.physical_root)
    environment["PWD"] = str(physical_cwd)

    supervised = supervise_command(
        argv=request.argv,
        cwd=str(physical_cwd),
        env=environment,
        timeout_ms=request.timeout_ms,
        max_output_bytes=request.max_output_bytes,
        cancellation=cancellation,
        start_hook=start_hook,
    )
    process = supervised.process_observation

    if not process.process_started:
        result = RunCommandResult.create(
            request_fingerprint=request.request_fingerprint,
            outcome="FAILED",
            process_started=False,
            exit_code=None,
            error_code="executor_start_failure",
        )
    elif supervised.refused_non_utf8:
        # Every byte is counted and fingerprinted in the stream observations;
        # only the retained *text* is refused.
        result = RunCommandResult.create(
            request_fingerprint=request.request_fingerprint,
            outcome="FAILED",
            process_started=True,
            stdout="",
            stderr="",
            exit_code=process.exit_code,
            error_code="non_utf8_output",
        )
    else:
        outcome = "OK" if (process.exit_code is not None and not process.timed_out and not process.cancelled) else "FAILED"
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


def _command_failure_code(process: ProcessObservation) -> str:
    if process.timed_out:
        return "command_timed_out"
    if process.cancelled:
        return "command_cancelled"
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
        self.effect_invocation_count = 0

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

        # 1. validate the experiment specification and the workspace binding.
        specification.validated()
        self._binding.validate_for_specification(specification)
        # 2. validate the proposal for that exact specification.
        proposal.validate_for_specification(specification)

        # 3. durably publish the canonical proposal before anything else.
        self._injector.check(FAULT_BEFORE_PROPOSAL_PUBLICATION)
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_PROPOSAL,
                object_id=proposal.proposal_id,
                record=proposal,
                fault_point=STAGE_PROPOSAL_PUBLICATION,
            )
        )
        self._injector.check(FAULT_AFTER_PROPOSAL_PUBLICATION)

        # 4. validate the decision for that exact proposal.
        decision.validate_for_proposal(proposal)
        receipts.append(
            self._store.publish_record(
                object_kind=OBJECT_KIND_DECISION, object_id=proposal.proposal_id, record=decision
            )
        )
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
        self._injector.check(FAULT_AFTER_STARTED_BEFORE_EFFECT)

        filesystem_before = observe_filesystem(self._binding.root_fd, phase="BEFORE_EFFECT")
        git_before = observe_git(self._binding.physical_root, phase="BEFORE_EFFECT")
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
        execution = self._cross_effect_boundary(proposal.tool_request)

        # 8. observe the result.
        filesystem_after = observe_filesystem(self._binding.root_fd, phase="AFTER_EFFECT")
        git_after = observe_git(self._binding.physical_root, phase="AFTER_EFFECT")
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
            final_reconciliation_state="RECONCILED_COMPLETE",
        )
        self._store.publish_record(
            object_kind=LEDGER_OBJECT_KIND,
            object_id=proposal.proposal_id,
            record=entry,
            fault_point=STAGE_RECONCILIATION_PUBLICATION,
        )
        reconciliation = reconcile_effect(
            self._store, run_id=proposal.run_identity.run_id, proposal_id=proposal.proposal_id
        )
        self._store.publish_record(
            object_kind=OBJECT_KIND_RECONCILIATION, object_id=proposal.proposal_id, record=reconciliation
        )

        # 11. verify the ledger from durable bytes, never from memory.
        verified = RunEffectLedger.verify(
            self._store, proposal.run_identity.run_id, tuple(item.proposal_id for item in self._ledger.entries) + (proposal.proposal_id,)
        )
        self._ledger.append(verified.entries[-1])

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

    def _cross_effect_boundary(self, request: ToolRequest) -> _CommandExecution:
        """The single point at which this process touches the workspace."""

        if self._effect_boundary_hook is not None:
            self._effect_boundary_hook()
        self.effect_invocation_count += 1
        if isinstance(request, ListFilesRequest):
            result: ToolResult = _list_files(self._binding, request)
        elif isinstance(request, ReadFileRequest):
            result = _read_file(self._binding, request)
        elif isinstance(request, WriteFileRequest):
            result = _write_file(self._binding, request)
        elif isinstance(request, RunCommandRequest):
            return _run_command(
                self._binding,
                request,
                cancellation=self._cancellation,
                start_hook=None,
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
    "EffectExecutionOutcome",
    "OBJECT_KIND_LIFECYCLE_STARTED",
    "OBJECT_KIND_PROPOSAL",
    "OBJECT_KIND_RECEIPT",
    "OBJECT_KIND_RECONCILIATION",
    "OBJECT_KIND_RESERVATION",
    "PRE_EFFECT_OBJECT_KINDS",
    "SANITIZED_ENVIRONMENT_BASE",
    "SharedEffectSubstrate",
    "WorkspaceBinding",
    "WorkspaceFailure",
    "WorkspaceRefusal",
    "observe_filesystem",
    "observe_git",
    "reconcile_effect",
    "workspace_content_digest",
]
