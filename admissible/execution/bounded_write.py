"""Neutral, local-only bounded ``write_file`` primitive.

This module deliberately owns the sole low-level write implementation shared
by the legacy bounded executor and the isolated V0 controller.  It has no
run-loop, evaluator, provider, projection, session, or controller imports.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re


DIAG_FORBIDDEN_OPERATION_CATEGORY = "forbidden_operation_category"
DIAG_NO_WORKSPACE_CONFIGURED = "no_workspace_configured"
DIAG_PATH_OUTSIDE_WORKSPACE = "path_outside_workspace"
DIAG_UNSUPPORTED_OPERATION = "unsupported_operation"
DIAG_WORKSPACE_AUTHORITY_CHANGED = "workspace_authority_changed"
DIAG_WORKSPACE_CONTAINMENT_CHANGED = "workspace_containment_changed"
DIAG_PHYSICAL_ATTESTATION_FAILED = "physical_attestation_failed"


class BoundedWriteError(ValueError):
    """A safe, bounded refusal emitted by the neutral write primitive."""

    def __init__(self, message: str, *, diagnostic: str) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic


class PhysicalAttestationError(BoundedWriteError):
    """A final physical file fact could not be independently confirmed."""


class CompletedWriteInterruption(BoundedWriteError):
    """One physical write completed, then a post-write authority check failed.

    The accomplished effect is carried on ``facts`` so the trusted caller can
    durably represent it instead of discarding a real file on disk.
    """

    def __init__(self, message: str, *, diagnostic: str, facts: "PhysicalFileFacts") -> None:
        super().__init__(message, diagnostic=diagnostic)
        self.facts = facts


@dataclass(frozen=True)
class BoundedWriteRequest:
    workspace: str | Path
    relative_path: str
    content: str
    workspace_authority: "WorkspaceAuthorityDescriptor | None" = None


@dataclass(frozen=True)
class BoundedWriteResult:
    relative_path: str
    resolved_target: str
    sha256: str
    byte_count: int
    overwritten: bool
    prior_sha256: str | None


@dataclass(frozen=True)
class WorkspaceAuthorityDescriptor:
    """Immutable configuration-time physical authority for a V0 workspace.

    The configured paths are retained so mutation-time validation can detect a
    logical path being rebound.  The resolved paths and identity keys are
    retained so a changed alias cannot silently become the new authority.
    ``filesystem_case_sensitive`` is explicit because identity comparison is
    a policy decision, not an accidental property of string casing.
    """

    configured_workspace_path: str
    canonical_workspace_path: str
    workspace_identity_key: str
    configured_allowed_live_root_path: str
    canonical_allowed_live_root_path: str
    allowed_live_root_identity_key: str
    configured_rejected_root_paths: tuple[str, ...]
    canonical_rejected_root_paths: tuple[str, ...]
    rejected_root_identity_keys: tuple[str, ...]
    filesystem_case_sensitive: bool

    @property
    def normalized_physical_identity(self) -> str:
        return self.workspace_identity_key

    @property
    def matching_allowed_live_root_identity(self) -> str:
        return self.allowed_live_root_identity_key

    @property
    def applicable_rejected_root_identities(self) -> tuple[str, ...]:
        return self.rejected_root_identity_keys

    @property
    def filesystem_case_sensitivity_policy(self) -> str:
        return "case_sensitive" if self.filesystem_case_sensitive else "case_insensitive"

    def to_dict(self) -> dict[str, object]:
        return {
            "configured_workspace_path": self.configured_workspace_path,
            "canonical_workspace_path": self.canonical_workspace_path,
            "workspace_identity_key": self.workspace_identity_key,
            "configured_allowed_live_root_path": self.configured_allowed_live_root_path,
            "canonical_allowed_live_root_path": self.canonical_allowed_live_root_path,
            "allowed_live_root_identity_key": self.allowed_live_root_identity_key,
            "configured_rejected_root_paths": list(self.configured_rejected_root_paths),
            "canonical_rejected_root_paths": list(self.canonical_rejected_root_paths),
            "rejected_root_identity_keys": list(self.rejected_root_identity_keys),
            "filesystem_case_sensitive": self.filesystem_case_sensitive,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "WorkspaceAuthorityDescriptor":
        expected = {
            "configured_workspace_path",
            "canonical_workspace_path",
            "workspace_identity_key",
            "configured_allowed_live_root_path",
            "canonical_allowed_live_root_path",
            "allowed_live_root_identity_key",
            "configured_rejected_root_paths",
            "canonical_rejected_root_paths",
            "rejected_root_identity_keys",
            "filesystem_case_sensitive",
        }
        if set(data) != expected:
            raise ValueError("invalid workspace authority descriptor fields")
        configured_rejected = data["configured_rejected_root_paths"]
        canonical_rejected = data["canonical_rejected_root_paths"]
        rejected_keys = data["rejected_root_identity_keys"]
        if not all(isinstance(value, list) for value in (configured_rejected, canonical_rejected, rejected_keys)):
            raise ValueError("workspace authority root identities must be lists")
        if not isinstance(data["filesystem_case_sensitive"], bool):
            raise ValueError("workspace authority case policy must be boolean")
        return cls(
            configured_workspace_path=data["configured_workspace_path"],  # type: ignore[arg-type]
            canonical_workspace_path=data["canonical_workspace_path"],  # type: ignore[arg-type]
            workspace_identity_key=data["workspace_identity_key"],  # type: ignore[arg-type]
            configured_allowed_live_root_path=data["configured_allowed_live_root_path"],  # type: ignore[arg-type]
            canonical_allowed_live_root_path=data["canonical_allowed_live_root_path"],  # type: ignore[arg-type]
            allowed_live_root_identity_key=data["allowed_live_root_identity_key"],  # type: ignore[arg-type]
            configured_rejected_root_paths=tuple(configured_rejected),  # type: ignore[arg-type]
            canonical_rejected_root_paths=tuple(canonical_rejected),  # type: ignore[arg-type]
            rejected_root_identity_keys=tuple(rejected_keys),  # type: ignore[arg-type]
            filesystem_case_sensitive=data["filesystem_case_sensitive"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class PhysicalFileFacts:
    """Facts independently read from the final physical file."""

    relative_path: str
    resolved_target: str
    physical_identity_key: str
    sha256: str
    byte_count: int
    content: bytes


_FORBIDDEN_NATURAL_LANGUAGE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bnpm\b",
        r"\byarn\b",
        r"\bpip\b",
        r"\bpnpm\b",
        r"\bbun\b",
        r"\bgit\s+(push|commit|clone|pull|fetch)\b",
        r"\bdeploy\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bssh\b",
        r"\bsubprocess\b",
        r"\bos\.system\b",
        r"\bshell\b",
        r"\bchmod\b",
        r"\brm\s+-rf\b",
    )
)
_NETWORK_SIDE_EFFECT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"\bfetch\s*\(",
        r"\bXMLHttpRequest\b",
        r"\bWebSocket\s*\(",
        r"\bEventSource\s*\(",
        r"https?://",
    )
)
_EXTERNAL_RESOURCE_REFERENCE_PATTERN = re.compile(r"(?:src|href)\s*=\s*[\"']\s*https?://", re.IGNORECASE)
_EXECUTABLE_OR_SECRET_CONTENT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bchild_process\b",
        r"\bsubprocess\.(?:run|popen|call)\s*\(",
        r"\bos\.system\s*\(",
        r"\bprocess\.env\b",
        r"\bDeno\.Command\s*\(",
        r"\bBun\.spawn\s*\(",
        r"\b(?:exec|spawn|system)Sync\s*\(",
    )
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def physical_identity_key(path: Path | str, *, case_sensitive: bool) -> str:
    normalized = os.path.normpath(str(path))
    if not case_sensitive:
        normalized = normalized.casefold()
    return ("case_sensitive:" if case_sensitive else "case_insensitive:") + normalized


def _path_is_beneath(root: Path, candidate: Path, *, case_sensitive: bool) -> bool:
    root_value = os.path.normpath(str(root))
    candidate_value = os.path.normpath(str(candidate))
    if not case_sensitive:
        root_value = root_value.casefold()
        candidate_value = candidate_value.casefold()
    try:
        return os.path.commonpath([root_value, candidate_value]) == root_value
    except ValueError:
        return False


def _matches_captured_identity(
    actual: Path,
    captured_canonical: str,
    captured_identity: str,
    *,
    case_sensitive: bool,
) -> bool:
    return (
        physical_identity_key(actual, case_sensitive=case_sensitive) == captured_identity
        and (not case_sensitive or str(actual) == captured_canonical)
    )


def _authority_error(diagnostic: str, message: str) -> BoundedWriteError:
    return BoundedWriteError(message, diagnostic=diagnostic)


def _resolve_authority_directory(raw: str, *, label: str) -> Path:
    candidate = Path(raw)
    if not candidate.exists() or not candidate.is_dir():
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            f"{label} is missing or is no longer a directory",
        )
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            f"{label} cannot be resolved: {exc}",
        ) from exc


def revalidate_workspace_authority(authority: WorkspaceAuthorityDescriptor) -> Path:
    """Revalidate every captured path and physical identity at mutation time."""

    case_sensitive = authority.filesystem_case_sensitive
    workspace = _resolve_authority_directory(
        authority.configured_workspace_path,
        label="configured workspace",
    )
    allowed = _resolve_authority_directory(
        authority.configured_allowed_live_root_path,
        label="allowed live root",
    )
    if not _matches_captured_identity(
        allowed,
        authority.canonical_allowed_live_root_path,
        authority.allowed_live_root_identity_key,
        case_sensitive=case_sensitive,
    ):
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            "configured allowed live root no longer resolves to its captured physical identity",
        )
    if len(authority.configured_rejected_root_paths) != len(authority.canonical_rejected_root_paths) or len(
        authority.canonical_rejected_root_paths
    ) != len(authority.rejected_root_identity_keys):
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            "captured rejected-root authority descriptor is inconsistent",
        )
    for configured, canonical, identity in zip(
        authority.configured_rejected_root_paths,
        authority.canonical_rejected_root_paths,
        authority.rejected_root_identity_keys,
        strict=True,
    ):
        rejected = _resolve_authority_directory(configured, label="rejected root")
        if not _matches_captured_identity(
            rejected,
            canonical,
            identity,
            case_sensitive=case_sensitive,
        ):
            raise _authority_error(
                DIAG_WORKSPACE_AUTHORITY_CHANGED,
                "configured rejected root no longer resolves to its captured physical identity",
            )
        # Rejected-root policy always takes precedence over the allowed root.
        if _path_is_beneath(rejected, workspace, case_sensitive=case_sensitive):
            raise _authority_error(
                DIAG_WORKSPACE_CONTAINMENT_CHANGED,
                "authorized workspace is beneath a rejected artifact root",
            )
    if not _path_is_beneath(allowed, workspace, case_sensitive=case_sensitive):
        raise _authority_error(
            DIAG_WORKSPACE_CONTAINMENT_CHANGED,
            "authorized workspace is no longer beneath the captured allowed live root",
        )
    if not _matches_captured_identity(
        workspace,
        authority.canonical_workspace_path,
        authority.workspace_identity_key,
        case_sensitive=case_sensitive,
    ):
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            "configured workspace no longer resolves to the originally authorized physical workspace",
        )
    return workspace


def _canonical_authorized_target(
    authority: WorkspaceAuthorityDescriptor,
    relative_path: str,
) -> Path:
    root = revalidate_workspace_authority(authority)
    raw = str(relative_path or ".").strip() or "."
    rel = Path(raw)
    if rel.is_absolute() or ".." in rel.parts:
        raise BoundedWriteError(f"path is outside workspace: {raw!r}", diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE)
    current = root
    for part in rel.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            try:
                resolved_component = current.resolve(strict=True)
            except OSError as exc:
                raise PhysicalAttestationError(
                    f"workspace component cannot be resolved: {part!r}",
                    diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
                ) from exc
            if not _path_is_beneath(root, resolved_component, case_sensitive=authority.filesystem_case_sensitive):
                raise _authority_error(
                    DIAG_WORKSPACE_CONTAINMENT_CHANGED,
                    "target component resolves outside the authorized workspace",
                )
    try:
        target = (root / rel).resolve(strict=False)
    except OSError as exc:
        raise PhysicalAttestationError(
            "target cannot be physically resolved",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        ) from exc
    if not _path_is_beneath(root, target, case_sensitive=authority.filesystem_case_sensitive):
        raise _authority_error(
            DIAG_WORKSPACE_CONTAINMENT_CHANGED,
            "target resolves outside the authorized workspace",
        )
    parent = target.parent.resolve(strict=False)
    if not _path_is_beneath(root, parent, case_sensitive=authority.filesystem_case_sensitive):
        raise _authority_error(
            DIAG_WORKSPACE_CONTAINMENT_CHANGED,
            "target parent resolves outside the authorized workspace",
        )
    return target


def attest_physical_file(
    *,
    authority: WorkspaceAuthorityDescriptor,
    relative_path: str,
    expected_resolved_target: str | None = None,
    expected_physical_identity_key: str | None = None,
    expected_content: bytes | None = None,
) -> PhysicalFileFacts:
    """Re-resolve and read a final file through the current authority."""

    target = _canonical_authorized_target(authority, relative_path)
    if not target.exists():
        raise PhysicalAttestationError(
            "final physical target does not exist",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    if not target.is_file():
        raise PhysicalAttestationError(
            "final physical target is not a regular file",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    try:
        resolved = target.resolve(strict=True)
        content = resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise PhysicalAttestationError(
            "final physical target cannot be read",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        ) from exc
    identity = physical_identity_key(resolved, case_sensitive=authority.filesystem_case_sensitive)
    if expected_resolved_target is not None and str(resolved) != expected_resolved_target:
        raise PhysicalAttestationError(
            "final physical target differs from the confirmed target",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    if expected_physical_identity_key is not None and identity != expected_physical_identity_key:
        raise PhysicalAttestationError(
            "final physical identity differs from the confirmed target",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    if expected_content is not None and content != expected_content:
        raise PhysicalAttestationError(
            "final file content differs from the confirmed completed write",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    return PhysicalFileFacts(
        relative_path=relative_path,
        resolved_target=str(resolved),
        physical_identity_key=identity,
        sha256=sha256_bytes(content),
        byte_count=len(content),
        content=content,
    )


def _original_authorized_root(authority: WorkspaceAuthorityDescriptor) -> Path:
    """Return the immutable originally authorized workspace, never re-following
    the configured logical path, which may since have been rebound."""

    root = Path(authority.canonical_workspace_path)
    if not root.exists() or not root.is_dir():
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            "originally authorized workspace is missing or is no longer a directory",
        )
    if physical_identity_key(root, case_sensitive=authority.filesystem_case_sensitive) != authority.workspace_identity_key:
        raise _authority_error(
            DIAG_WORKSPACE_AUTHORITY_CHANGED,
            "originally authorized workspace no longer has its captured physical identity",
        )
    return root


def attest_completed_write_against_original_authority(
    *,
    authority: WorkspaceAuthorityDescriptor,
    relative_path: str,
    expected_resolved_target: str | None = None,
    expected_physical_identity_key: str | None = None,
    expected_content: bytes | None = None,
) -> PhysicalFileFacts:
    """Attest an already accomplished write against the original authority.

    Used when the logical workspace path may have been rebound after a write
    physically completed.  A rebound logical path must never be followed to
    attest an earlier effect, so containment is checked against the immutable
    canonical workspace captured in ``WorkspaceAuthorityDescriptor``.
    """

    root = _original_authorized_root(authority)
    case_sensitive = authority.filesystem_case_sensitive
    raw = str(relative_path or "").strip()
    rel = Path(raw) if raw else Path(".")
    if not raw or rel.is_absolute() or ".." in rel.parts:
        raise BoundedWriteError(f"path is outside workspace: {raw!r}", diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE)
    target = root / rel
    if not target.exists() or not target.is_file():
        raise PhysicalAttestationError(
            "completed physical write is missing under the originally authorized workspace",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    try:
        resolved = target.resolve(strict=True)
        content = resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise PhysicalAttestationError(
            "completed physical write cannot be read",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        ) from exc
    if not _path_is_beneath(root, resolved, case_sensitive=case_sensitive):
        raise _authority_error(
            DIAG_WORKSPACE_CONTAINMENT_CHANGED,
            "completed write does not remain beneath the originally authorized workspace",
        )
    identity = physical_identity_key(resolved, case_sensitive=case_sensitive)
    if expected_resolved_target is not None and str(resolved) != expected_resolved_target:
        raise PhysicalAttestationError(
            "completed write differs from the confirmed target",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    if expected_physical_identity_key is not None and identity != expected_physical_identity_key:
        raise PhysicalAttestationError(
            "completed write physical identity differs from the confirmed target",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    if expected_content is not None and content != expected_content:
        raise PhysicalAttestationError(
            "completed write content differs from the confirmed completed write",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    return PhysicalFileFacts(
        relative_path=relative_path,
        resolved_target=str(resolved),
        physical_identity_key=identity,
        sha256=sha256_bytes(content),
        byte_count=len(content),
        content=content,
    )


def validate_workspace_path(workspace_path: str | Path | None) -> Path:
    if workspace_path is None or not str(workspace_path).strip():
        raise BoundedWriteError("no workspace configured for bounded local execution", diagnostic=DIAG_NO_WORKSPACE_CONFIGURED)
    workspace = Path(str(workspace_path).strip())
    if not workspace.is_dir():
        raise BoundedWriteError(
            f"workspace path does not exist or is not a directory: {workspace}",
            diagnostic=DIAG_NO_WORKSPACE_CONFIGURED,
        )
    return workspace.resolve()


def validate_relative_path_inside_workspace(workspace: Path, relative_path: str) -> Path:
    workspace = workspace.resolve()
    raw = str(relative_path or ".").strip() or "."
    rel = Path(raw)
    if rel.is_absolute() or ".." in rel.parts:
        raise BoundedWriteError(f"path is outside workspace: {raw!r}", diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE)
    target = (workspace / rel).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise BoundedWriteError(f"path resolves outside workspace: {raw!r}", diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE) from exc
    for ancestor in [target, *target.parents]:
        if ancestor == workspace:
            break
        if ancestor.is_symlink():
            try:
                ancestor.resolve().relative_to(workspace)
            except ValueError as exc:
                raise BoundedWriteError(f"symlink escape outside workspace: {raw!r}", diagnostic=DIAG_PATH_OUTSIDE_WORKSPACE) from exc
    return target


def _looks_like_forbidden_natural_language(text: str) -> bool:
    return any(pattern.search(text) for pattern in _FORBIDDEN_NATURAL_LANGUAGE_PATTERNS)


def forbidden_write_content_reason(path: str, content: str) -> str | None:
    """The established bounded-executor content guard, shared without legacy imports."""

    extension = Path(str(path).replace("\\", "/")).suffix.lower()
    if any(pattern.search(content) for pattern in _EXECUTABLE_OR_SECRET_CONTENT_PATTERNS):
        return "forbidden executable-command or secret-reference content"
    network = any(pattern.search(content) for pattern in _NETWORK_SIDE_EFFECT_PATTERNS)
    if extension == ".css":
        return "forbidden network reference in write content" if network else None
    if extension == ".js":
        return "forbidden network call in write content" if network else None
    if extension in (".html", ".htm"):
        if _EXTERNAL_RESOURCE_REFERENCE_PATTERN.search(content):
            return "forbidden external resource reference in write content"
        return "forbidden network call in write content" if network else None
    if extension == ".md":
        return "forbidden network call in write content" if network else None
    return "forbidden operation string in write content" if _looks_like_forbidden_natural_language(content) else None


def validate_bounded_write_content(relative_path: str, content: str) -> None:
    if not isinstance(relative_path, str) or not isinstance(content, str):
        raise BoundedWriteError("write_file path and content must be strings", diagnostic=DIAG_UNSUPPORTED_OPERATION)
    violation = forbidden_write_content_reason(relative_path, content)
    if violation is not None:
        raise BoundedWriteError(violation, diagnostic=DIAG_FORBIDDEN_OPERATION_CATEGORY)


def execute_bounded_write(request: BoundedWriteRequest) -> BoundedWriteResult:
    """Validate and write one UTF-8 local file with mutation-time authority checks.

    The final validation and the write syscall are intentionally still a
    normal operating-system race window.  V0 does not claim impossible
    race-free filesystem security against a hostile concurrent mutator.
    """

    validate_bounded_write_content(request.relative_path, request.content)
    authority = request.workspace_authority
    if authority is None:
        workspace = validate_workspace_path(request.workspace)
        target = validate_relative_path_inside_workspace(workspace, request.relative_path)
    else:
        workspace = revalidate_workspace_authority(authority)
        target = _canonical_authorized_target(authority, request.relative_path)

    def revalidate_unbound_workspace() -> None:
        if authority is not None:
            return
        current = validate_workspace_path(request.workspace)
        if os.path.normcase(str(current)) != os.path.normcase(str(workspace)):
            raise BoundedWriteError(
                "configured workspace changed during bounded write",
                diagnostic=DIAG_WORKSPACE_AUTHORITY_CHANGED,
            )

    if target.exists() and not target.is_file():
        raise PhysicalAttestationError(
            "bounded write target is not a regular file",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    prior_sha256 = sha256_bytes(target.read_bytes()) if target.is_file() else None

    if authority is not None:
        # Parent creation is itself mutation-capable.  Revalidate both before
        # and after it, then resolve the target again before opening it.
        revalidate_workspace_authority(authority)
    else:
        revalidate_unbound_workspace()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BoundedWriteError(
            "bounded write parent directory could not be created",
            diagnostic=DIAG_WORKSPACE_CONTAINMENT_CHANGED,
        ) from exc
    if authority is not None:
        revalidate_workspace_authority(authority)
        target = _canonical_authorized_target(authority, request.relative_path)
    else:
        revalidate_unbound_workspace()
        target = validate_relative_path_inside_workspace(workspace, request.relative_path)
    if target.exists() and not target.is_file():
        raise PhysicalAttestationError(
            "bounded write target became a non-regular file",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        )
    data = request.content.encode("utf-8")
    try:
        target.write_bytes(data)
    except OSError as exc:
        raise BoundedWriteError(
            "bounded write could not complete",
            diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
        ) from exc
    if authority is not None:
        # The write syscall has completed.  Attest the accomplished effect
        # against the immutable original authority first, so a later authority
        # change interrupts the batch without erasing a real physical file.
        facts = attest_completed_write_against_original_authority(
            authority=authority,
            relative_path=request.relative_path,
            expected_content=data,
        )
        try:
            revalidate_workspace_authority(authority)
        except BoundedWriteError as exc:
            raise CompletedWriteInterruption(
                f"workspace authority changed after a completed physical write: {exc}",
                diagnostic=exc.diagnostic,
                facts=facts,
            ) from exc
        resolved_after_write = facts.resolved_target
        digest = facts.sha256
        byte_count = facts.byte_count
    else:
        revalidate_unbound_workspace()
        final_target = target.resolve(strict=True)
        if not final_target.is_file():
            raise PhysicalAttestationError(
                "bounded write final target is not a regular file",
                diagnostic=DIAG_PHYSICAL_ATTESTATION_FAILED,
            )
        final_data = final_target.read_bytes()
        resolved_after_write = str(final_target)
        digest = sha256_bytes(final_data)
        byte_count = len(final_data)
    return BoundedWriteResult(
        relative_path=request.relative_path,
        resolved_target=resolved_after_write,
        sha256=digest,
        byte_count=byte_count,
        overwritten=prior_sha256 is not None,
        prior_sha256=prior_sha256,
    )
