"""Read-only deterministic material-checkpoint capture over a local Git tree."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Any
import weakref

from admissible.delegated_gate.canonical import (
    fingerprint,
    require_identifier,
    require_safe_relative_path,
    require_strict_int,
)
from admissible.delegated_gate.models import (
    ArtifactReference,
    CHECKPOINT_SCHEMA_VERSION,
    Checkpoint,
    CommandEvidence,
    EvidenceKind,
    EvidenceStatus,
    GateContract,
    GitEvidence,
    TreeEvidence,
    VerificationCommand,
)
from admissible.managed_process import ManagedOneshotResult, run_managed_oneshot


class CheckpointCaptureError(RuntimeError):
    pass


class _CapturedCheckpoint:
    """Opaque, non-copyable handle to one private boundary issuance record.

    The handle intentionally carries no checkpoint, marker, nonce, or consumed
    state.  Exact-object authority lives only in the weak private registry
    below, which is an ordinary in-process API boundary rather than a defense
    against hostile interpreter introspection.
    """

    __slots__ = ("__weakref__",)

    def __copy__(self) -> "_CapturedCheckpoint":
        raise TypeError("captured checkpoint is transient and cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "_CapturedCheckpoint":
        raise TypeError("captured checkpoint is transient and cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("captured checkpoint is transient and cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError("captured checkpoint is transient and cannot be serialized")


@dataclass(frozen=True)
class _IssuedCapture:
    capture_ref: weakref.ReferenceType[_CapturedCheckpoint]
    checkpoint: Checkpoint
    session_id: str
    gate_id: str
    execution_attempt_index: int
    checkpoint_fingerprint: str


_CAPTURE_ISSUANCE_REGISTRY: dict[int, _IssuedCapture] = {}


def _capture_identity(capture: _CapturedCheckpoint) -> int:
    """Return the only registry key; authority never uses equality or hashing."""

    return id(capture)


def _issue_captured_checkpoint(checkpoint: Checkpoint) -> _CapturedCheckpoint:
    checkpoint = checkpoint.validated()
    capture = _CapturedCheckpoint()
    capture_identity = _capture_identity(capture)

    def remove_dead_capture(reference: weakref.ReferenceType[_CapturedCheckpoint]) -> None:
        current = _CAPTURE_ISSUANCE_REGISTRY.get(capture_identity)
        if current is not None and current.capture_ref is reference:
            del _CAPTURE_ISSUANCE_REGISTRY[capture_identity]

    capture_ref = weakref.ref(capture, remove_dead_capture)
    existing = _CAPTURE_ISSUANCE_REGISTRY.get(capture_identity)
    if existing is not None:
        if existing.capture_ref() is not None:
            raise RuntimeError("checkpoint capture identity collision is still live")
        del _CAPTURE_ISSUANCE_REGISTRY[capture_identity]
    _CAPTURE_ISSUANCE_REGISTRY[capture_identity] = _IssuedCapture(
        capture_ref=capture_ref,
        checkpoint=checkpoint,
        session_id=checkpoint.session_id,
        gate_id=checkpoint.gate_id,
        execution_attempt_index=checkpoint.execution_attempt_index,
        checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
    )
    return capture


def _issued_capture_for(
    capture_result: object,
    *,
    session_id: str,
    gate_id: str,
    execution_attempt_index: int,
    checkpoint_fingerprint: str | None = None,
) -> _IssuedCapture:
    if type(capture_result) is not _CapturedCheckpoint:
        raise ValueError("checkpoint recording requires a boundary-issued capture result")
    capture_identity = _capture_identity(capture_result)
    issuance = _CAPTURE_ISSUANCE_REGISTRY.get(capture_identity)
    if issuance is None or issuance.capture_ref() is not capture_result:
        raise ValueError("checkpoint capture result has no protocol issuance authority")
    checkpoint = issuance.checkpoint.validated()
    if (
        issuance.session_id != checkpoint.session_id
        or issuance.gate_id != checkpoint.gate_id
        or issuance.execution_attempt_index != checkpoint.execution_attempt_index
        or issuance.checkpoint_fingerprint != checkpoint.checkpoint_fingerprint
    ):
        raise ValueError("checkpoint capture issuance record is internally inconsistent")
    if checkpoint.session_id != session_id or checkpoint.gate_id != gate_id:
        raise ValueError("checkpoint identity is bound to another session or gate")
    if checkpoint.execution_attempt_index != execution_attempt_index:
        raise ValueError("checkpoint execution attempt does not match the active phase")
    if checkpoint_fingerprint is not None and checkpoint.checkpoint_fingerprint != checkpoint_fingerprint:
        raise ValueError("checkpoint capture result is bound to another checkpoint")
    return issuance


def _peek_issued_checkpoint(
    capture_result: object,
    *,
    session_id: str,
    gate_id: str,
    execution_attempt_index: int,
) -> Checkpoint:
    return _issued_capture_for(
        capture_result,
        session_id=session_id,
        gate_id=gate_id,
        execution_attempt_index=execution_attempt_index,
    ).checkpoint


def _consume_issued_checkpoint(
    capture_result: object,
    *,
    session_id: str,
    gate_id: str,
    execution_attempt_index: int,
    checkpoint_fingerprint: str,
) -> None:
    issuance = _issued_capture_for(
        capture_result,
        session_id=session_id,
        gate_id=gate_id,
        execution_attempt_index=execution_attempt_index,
        checkpoint_fingerprint=checkpoint_fingerprint,
    )
    capture_identity = _capture_identity(capture_result)
    if _CAPTURE_ISSUANCE_REGISTRY.get(capture_identity) is not issuance:
        raise ValueError("checkpoint capture result has already been consumed")
    del _CAPTURE_ISSUANCE_REGISTRY[capture_identity]


@dataclass(frozen=True)
class _TreeSnapshot:
    tree_hash: str
    file_count: int


def _inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _tree_snapshot(root: Path) -> _TreeSnapshot:
    if not root.is_dir():
        raise CheckpointCaptureError("checkpoint target repository does not exist")
    entries: list[tuple[str, str, int]] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            path = base / name
            rel = path.relative_to(root).as_posix()
            if name == ".git":
                continue
            if path.is_symlink():
                raise CheckpointCaptureError(f"symlinked directory is outside checkpoint authority: {rel}")
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            path = base / name
            rel = path.relative_to(root).as_posix()
            if name == ".git":
                continue
            if path.is_symlink():
                raise CheckpointCaptureError(f"symlinked file is outside checkpoint authority: {rel}")
            data = path.read_bytes()
            entries.append((rel, hashlib.sha256(data).hexdigest(), len(data)))
    entries.sort(key=lambda item: item[0])
    digest = hashlib.sha256()
    for rel, sha256, byte_count in entries:
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(byte_count).encode("ascii"))
        digest.update(b"\n")
    return _TreeSnapshot(tree_hash=digest.hexdigest(), file_count=len(entries))


def _run(argv: list[str], *, cwd: Path, timeout: int, max_capture_bytes: int) -> ManagedOneshotResult:
    try:
        return run_managed_oneshot(
            argv,
            cwd=str(cwd),
            env=None,
            timeout_seconds=timeout,
            max_capture_bytes=max_capture_bytes,
        )
    except Exception as exc:
        raise CheckpointCaptureError(f"managed checkpoint command failed to start: {exc}") from exc


def _git_observation(repository: Path) -> tuple[str | None, str]:
    root = _run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repository,
        timeout=15,
        max_capture_bytes=8192,
    )
    if root.returncode != 0 or root.timed_out or not root.cleanup_proven:
        raise CheckpointCaptureError("target is not a cleanly observable local Git repository")
    observed_root = Path(root.stdout.strip()).resolve()
    if observed_root != repository:
        raise CheckpointCaptureError("checkpoint target must be the exact Git repository root")
    head_result = _run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=repository,
        timeout=15,
        max_capture_bytes=8192,
    )
    if head_result.timed_out or not head_result.cleanup_proven:
        raise CheckpointCaptureError("Git HEAD observation is inconclusive")
    head = head_result.stdout.strip().lower() if head_result.returncode == 0 else None
    if head is not None and (len(head) != 40 or any(c not in "0123456789abcdef" for c in head)):
        raise CheckpointCaptureError("Git HEAD observation is malformed")
    status_result = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
        timeout=30,
        max_capture_bytes=1024 * 1024,
    )
    if status_result.returncode != 0 or status_result.timed_out or not status_result.cleanup_proven:
        raise CheckpointCaptureError("Git worktree status observation is inconclusive")
    return head, status_result.stdout


@dataclass(frozen=True)
class _ArtifactPlan:
    artifact_id: str
    purpose: str
    relative_path: str
    destination: Path


@dataclass(frozen=True)
class _ArtifactWrite:
    references: tuple[ArtifactReference, ...]
    owned_artifacts: tuple[_OwnedArtifact, ...]
    root_anchor: _ArtifactRootAnchor | None


@dataclass(frozen=True)
class _FilesystemIdentity:
    device: int
    inode: int


@dataclass(frozen=True)
class _ArtifactRootAnchor:
    lexical_root: Path
    created_by_capture: bool
    identity: _FilesystemIdentity
    validated_non_redirecting_directory: bool


@dataclass(frozen=True)
class _OwnedArtifact:
    lexical_path: Path
    identity: _FilesystemIdentity | None
    created_by_capture: bool


def _lexical_absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _is_redirecting_path(path: Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction is not None and isjunction(os.fspath(path)))


def _path_exists_without_following(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CheckpointCaptureError(f"artifact path cannot be inspected: {exc}") from exc
    return True


def _filesystem_identity(metadata: os.stat_result) -> _FilesystemIdentity:
    return _FilesystemIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _validate_existing_directory_components(path: Path) -> None:
    """Reject pre-existing redirection before treating a lexical path as rooted."""

    anchor = Path(path.anchor)
    current = anchor
    for part in path.parts[1:]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CheckpointCaptureError(f"artifact path cannot be inspected: {exc}") from exc
        if _is_redirecting_path(current, metadata):
            raise CheckpointCaptureError("checkpoint artifact path contains a redirecting link or reparse point")
        if not stat.S_ISDIR(metadata.st_mode):
            raise CheckpointCaptureError("checkpoint artifact path component must be a directory")


def _validate_artifact_destination(destination: Path, *, artifact_root: Path) -> None:
    _validate_existing_directory_components(destination.parent)
    try:
        resolved_root = artifact_root.resolve(strict=False)
        resolved_destination = destination.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise CheckpointCaptureError(f"artifact destination is invalid: {exc}") from exc
    if resolved_destination == resolved_root or not _inside(resolved_destination, resolved_root):
        raise CheckpointCaptureError("checkpoint artifact destination escapes its root")


def _anchor_artifact_root(
    artifact_root: Path,
    *,
    created_by_capture: bool,
) -> _ArtifactRootAnchor:
    _validate_existing_directory_components(artifact_root)
    try:
        metadata = os.lstat(artifact_root)
    except OSError as exc:
        raise CheckpointCaptureError(f"artifact root cannot be anchored: {exc}") from exc
    if _is_redirecting_path(artifact_root, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise CheckpointCaptureError("artifact root is not a real non-redirecting directory")
    return _ArtifactRootAnchor(
        lexical_root=artifact_root,
        created_by_capture=created_by_capture,
        identity=_filesystem_identity(metadata),
        validated_non_redirecting_directory=True,
    )


def _validate_root_anchor(anchor: _ArtifactRootAnchor) -> str | None:
    try:
        _validate_existing_directory_components(anchor.lexical_root)
        metadata = os.lstat(anchor.lexical_root)
    except (CheckpointCaptureError, OSError):
        return f"could not verify capture-created artifact root {anchor.lexical_root}"
    if (
        _is_redirecting_path(anchor.lexical_root, metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or _filesystem_identity(metadata) != anchor.identity
    ):
        return f"capture-created artifact root changed or redirects {anchor.lexical_root}"
    return None


def _validate_owned_artifact(
    artifact: _OwnedArtifact,
    *,
    root_anchor: _ArtifactRootAnchor,
) -> str | None:
    root_error = _validate_root_anchor(root_anchor)
    if root_error is not None:
        return root_error
    try:
        _validate_existing_directory_components(artifact.lexical_path.parent)
        metadata = os.lstat(artifact.lexical_path)
    except (CheckpointCaptureError, OSError):
        return f"could not verify capture-created artifact {artifact.lexical_path}"
    if artifact.identity is None:
        return f"capture-created artifact has no filesystem identity {artifact.lexical_path}"
    if (
        _is_redirecting_path(artifact.lexical_path, metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or _filesystem_identity(metadata) != artifact.identity
    ):
        return f"capture-created artifact changed or redirects {artifact.lexical_path}"
    return None


def _resolve_artifact_root(value: str | Path, *, repository: Path) -> Path:
    if not isinstance(value, (str, Path)) or "\x00" in str(value):
        raise CheckpointCaptureError("artifact directory is invalid")
    try:
        artifact_root = _lexical_absolute_path(value)
    except (OSError, ValueError) as exc:
        raise CheckpointCaptureError(f"artifact directory is invalid: {exc}") from exc
    _validate_existing_directory_components(artifact_root)
    try:
        resolved_root = artifact_root.resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise CheckpointCaptureError(f"artifact directory is invalid: {exc}") from exc
    if _inside(resolved_root, repository):
        raise CheckpointCaptureError("checkpoint artifacts must be outside the target repository")
    return artifact_root


def _preflight_artifact_plan(
    *,
    artifact_root: Path,
    session_id: str,
    gate_contract: GateContract,
    execution_attempt_index: int,
) -> tuple[_ArtifactPlan, ...]:
    plans: list[_ArtifactPlan] = []
    artifact_ids: set[str] = set()
    relative_paths: set[str] = set()
    for command in gate_contract.checkpoint_verification_commands:
        evidence_id = f"command.{command.command_id}"
        require_identifier(evidence_id, "command evidence ID")
        prefix = (
            f"{session_id}.{gate_contract.gate_id}.attempt-{execution_attempt_index}.{command.command_id}"
        )
        for purpose in ("stdout", "stderr"):
            artifact_id = f"{prefix}.{purpose}"
            relative_path = f"{artifact_id}.txt"
            require_identifier(artifact_id, "artifact ID")
            require_safe_relative_path(relative_path, "artifact relative_path")
            if artifact_id in artifact_ids or relative_path in relative_paths:
                raise CheckpointCaptureError("checkpoint artifact plan contains a collision")
            destination = artifact_root / relative_path
            _validate_artifact_destination(destination, artifact_root=artifact_root)
            if _path_exists_without_following(destination):
                raise CheckpointCaptureError("checkpoint artifact destination already exists")
            artifact_ids.add(artifact_id)
            relative_paths.add(relative_path)
            plans.append(
                _ArtifactPlan(
                    artifact_id=artifact_id,
                    purpose=purpose,
                    relative_path=relative_path,
                    destination=destination,
                )
            )
    return tuple(plans)


def _write_artifacts(
    *,
    artifact_root: Path,
    planned_outputs: tuple[tuple[_ArtifactPlan, str, bool], ...],
) -> _ArtifactWrite:
    if not planned_outputs:
        return _ArtifactWrite(references=(), owned_artifacts=(), root_anchor=None)
    planned_ids = [plan.artifact_id for plan, _, _ in planned_outputs]
    planned_paths = [plan.relative_path for plan, _, _ in planned_outputs]
    planned_destinations = [plan.destination for plan, _, _ in planned_outputs]
    if (
        len(set(planned_ids)) != len(planned_ids)
        or len(set(planned_paths)) != len(planned_paths)
        or len(set(planned_destinations)) != len(planned_destinations)
    ):
        raise CheckpointCaptureError("checkpoint artifact plan contains a collision")
    root_missing_before_write = not _path_exists_without_following(artifact_root)
    created_root = False
    root_anchor: _ArtifactRootAnchor | None = None
    owned_artifacts: list[_OwnedArtifact] = []
    references: list[ArtifactReference] = []
    try:
        if root_missing_before_write:
            artifact_root.mkdir(parents=True, exist_ok=False)
            created_root = True
        root_anchor = _anchor_artifact_root(artifact_root, created_by_capture=created_root)
        for plan, content, truncated in planned_outputs:
            _validate_artifact_destination(plan.destination, artifact_root=artifact_root)
            if _path_exists_without_following(plan.destination):
                raise CheckpointCaptureError("checkpoint artifact destination appeared during capture")
            data = content.encode("utf-8")
            try:
                handle = plan.destination.open("xb")
            except FileExistsError as exc:
                raise CheckpointCaptureError("checkpoint artifact write would overwrite evidence") from exc
            try:
                identity = _filesystem_identity(os.fstat(handle.fileno()))
            except OSError:
                owned_artifacts.append(
                    _OwnedArtifact(
                        lexical_path=plan.destination,
                        identity=None,
                        created_by_capture=True,
                    )
                )
                handle.close()
                raise
            owned_artifacts.append(
                _OwnedArtifact(
                    lexical_path=plan.destination,
                    identity=identity,
                    created_by_capture=True,
                )
            )
            try:
                with handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError as exc:  # pragma: no cover - defensive after exclusive open
                raise CheckpointCaptureError("checkpoint artifact write would overwrite evidence") from exc
            references.append(
                ArtifactReference(
                    artifact_id=plan.artifact_id,
                    purpose=plan.purpose,
                    relative_path=plan.relative_path,
                    sha256=hashlib.sha256(data).hexdigest(),
                    byte_count=len(data),
                    truncated=truncated,
                ).validated()
            )
        return _ArtifactWrite(
            references=tuple(references),
            owned_artifacts=tuple(owned_artifacts),
            root_anchor=root_anchor,
        )
    except Exception as exc:
        cleanup_errors = (
            _cleanup_capture_artifacts(
                owned_artifacts=tuple(owned_artifacts),
                root_anchor=root_anchor,
            )
            if root_anchor is not None or owned_artifacts
            else ()
        )
        if cleanup_errors:
            raise CheckpointCaptureError(
                "checkpoint artifact write failed and cleanup failed: " + "; ".join(cleanup_errors)
            ) from exc
        if isinstance(exc, CheckpointCaptureError):
            raise
        raise CheckpointCaptureError(f"checkpoint artifact write failed: {exc}") from exc


def _cleanup_capture_artifacts(
    *,
    owned_artifacts: tuple[_OwnedArtifact, ...],
    root_anchor: _ArtifactRootAnchor | None,
) -> tuple[str, ...]:
    errors: list[str] = []
    if root_anchor is None:
        return ("could not verify capture-created artifact root",) if owned_artifacts else ()
    for artifact in reversed(owned_artifacts):
        if not artifact.created_by_capture:
            continue
        validation_error = _validate_owned_artifact(artifact, root_anchor=root_anchor)
        if validation_error is not None:
            errors.append(validation_error)
            continue
        try:
            artifact.lexical_path.unlink()
        except OSError:
            errors.append(f"could not remove capture-created artifact {artifact.lexical_path}")
    if root_anchor.created_by_capture and not errors:
        root_error = _validate_root_anchor(root_anchor)
        if root_error is not None:
            errors.append(root_error)
            return tuple(errors)
        try:
            root_anchor.lexical_root.rmdir()
        except FileNotFoundError:
            errors.append(f"could not remove capture-created artifact root {root_anchor.lexical_root}")
        except OSError:
            errors.append(f"could not remove capture-created artifact root {root_anchor.lexical_root}")
    return tuple(errors)


def _cleanup_written_artifacts(write: _ArtifactWrite) -> None:
    errors = _cleanup_capture_artifacts(
        owned_artifacts=write.owned_artifacts,
        root_anchor=write.root_anchor,
    )
    if errors:
        raise CheckpointCaptureError("checkpoint artifact cleanup failed: " + "; ".join(errors))


def _checkpoint_from_observations(
    *,
    session_id: str,
    gate_id: str,
    execution_attempt_index: int,
    material_tree_hash: str,
    git_head: str | None,
    git_worktree_status: str,
    evidence_records: tuple[TreeEvidence | GitEvidence | CommandEvidence, ...],
    artifact_references: tuple[ArtifactReference, ...],
) -> Checkpoint:
    provisional = Checkpoint(
        schema_version=CHECKPOINT_SCHEMA_VERSION,
        session_id=session_id,
        gate_id=gate_id,
        execution_attempt_index=execution_attempt_index,
        material_tree_hash=material_tree_hash,
        git_head=git_head,
        git_worktree_status=git_worktree_status,
        evidence_records=evidence_records,
        artifact_references=artifact_references,
        checkpoint_fingerprint="0" * 64,
    )
    return Checkpoint(
        **{**provisional.__dict__, "checkpoint_fingerprint": fingerprint(provisional._body())}
    ).validated()


def capture_checkpoint(
    *,
    repository: str | Path,
    artifact_directory: str | Path,
    session_id: str,
    gate_contract: GateContract,
    execution_attempt_index: int,
) -> object:
    """Capture exact material/Git/command evidence without trusting executor data.

    The artifact directory must be outside the target repository. The immutable
    gate contract is the sole source of verification argv. Any worktree, HEAD,
    or material-tree change during capture rejects the checkpoint.
    """

    try:
        gate_contract.validated()
        require_identifier(session_id, "checkpoint session_id")
        require_identifier(gate_contract.gate_id, "checkpoint gate_id")
        require_strict_int(
            execution_attempt_index,
            "checkpoint execution_attempt_index",
            minimum=0,
            maximum=1,
        )
        repo = Path(repository).resolve()
        artifacts = _resolve_artifact_root(artifact_directory, repository=repo)
        artifact_plan = _preflight_artifact_plan(
            artifact_root=artifacts,
            session_id=session_id,
            gate_contract=gate_contract,
            execution_attempt_index=execution_attempt_index,
        )
    except CheckpointCaptureError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise CheckpointCaptureError(f"checkpoint capture preflight failed: {exc}") from exc

    before_tree = _tree_snapshot(repo)
    before_head, before_status = _git_observation(repo)
    command_results: list[tuple[VerificationCommand, ManagedOneshotResult]] = []

    for command in gate_contract.checkpoint_verification_commands:
        result = _run(
            list(command.argv),
            cwd=repo,
            timeout=command.timeout_seconds,
            max_capture_bytes=command.max_capture_bytes,
        )
        command_results.append((command, result))

    after_tree = _tree_snapshot(repo)
    after_head, after_status = _git_observation(repo)
    if (
        after_tree != before_tree
        or after_head != before_head
        or after_status != before_status
    ):
        raise CheckpointCaptureError("repository mutated during checkpoint capture")

    planned_outputs: list[tuple[_ArtifactPlan, str, bool]] = []
    for index, (_, result) in enumerate(command_results):
        stdout_plan = artifact_plan[index * 2]
        stderr_plan = artifact_plan[index * 2 + 1]
        planned_outputs.extend(
            (
                (stdout_plan, result.stdout, result.process_result.output_truncated),
                (stderr_plan, result.stderr, result.process_result.output_truncated),
            )
        )
    artifact_write = _write_artifacts(
        artifact_root=artifacts,
        planned_outputs=tuple(planned_outputs),
    )
    try:
        artifact_refs = artifact_write.references
        evidence: list[TreeEvidence | GitEvidence | CommandEvidence] = []
        for index, (command, result) in enumerate(command_results):
            stdout_ref = artifact_refs[index * 2]
            stderr_ref = artifact_refs[index * 2 + 1]
            if result.timed_out or not result.cleanup_proven:
                status = EvidenceStatus.INCONCLUSIVE
            elif result.returncode == 0:
                status = EvidenceStatus.PASSED
            else:
                status = EvidenceStatus.FAILED
            evidence.append(
                CommandEvidence(
                    evidence_id=f"command.{command.command_id}",
                    kind=EvidenceKind.VERIFICATION_COMMAND,
                    status=status,
                    command_id=command.command_id,
                    argv=command.argv,
                    exit_code=result.returncode,
                    timed_out=result.timed_out,
                    cleanup_proven=result.cleanup_proven,
                    output_truncated=result.process_result.output_truncated,
                    stdout_artifact_id=stdout_ref.artifact_id,
                    stderr_artifact_id=stderr_ref.artifact_id,
                ).validated()
            )

        typed_evidence = (
            TreeEvidence(
                evidence_id="target-tree",
                kind=EvidenceKind.TARGET_TREE,
                status=EvidenceStatus.OBSERVED,
                tree_hash=after_tree.tree_hash,
                file_count=after_tree.file_count,
            ).validated(),
            GitEvidence(
                evidence_id="git-state",
                kind=EvidenceKind.GIT_STATE,
                status=EvidenceStatus.OBSERVED,
                head=after_head,
                porcelain_status=after_status,
            ).validated(),
            *evidence,
        )
        checkpoint = _checkpoint_from_observations(
            session_id=session_id,
            gate_id=gate_contract.gate_id,
            execution_attempt_index=execution_attempt_index,
            material_tree_hash=after_tree.tree_hash,
            git_head=after_head,
            git_worktree_status=after_status,
            evidence_records=tuple(typed_evidence),
            artifact_references=artifact_refs,
        )
    except Exception as exc:
        try:
            _cleanup_written_artifacts(artifact_write)
        except CheckpointCaptureError as cleanup_exc:
            raise CheckpointCaptureError(
                f"checkpoint artifact assembly failed and cleanup failed: {cleanup_exc}"
            ) from exc
        raise CheckpointCaptureError(f"checkpoint artifact assembly failed: {exc}") from exc
    return _issue_captured_checkpoint(checkpoint)
