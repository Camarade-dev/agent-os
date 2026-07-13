"""Physical workspace containment and target identity for V0 executor receipts.

The reducer accepts only immutable, already-validated target identities.  This
module is deliberately outside the reducer because resolving a workspace is
physical I/O.  Ordinary symlinks and the Windows junctions exposed through
``Path.resolve`` are handled fail-closed.  Hostile concurrent filesystem
mutation and vendor-specific reparse behavior that standard Python cannot
observe remain outside this V0 guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterable

from admissible.v0_controller.state import WorkspacePolicy


class WorkspaceGuardError(ValueError):
    """Typed rejection before an executor receipt can enter V0 state."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FilesystemIdentityPolicy:
    """Explicit physical-name semantics, derived from the target host by default.

    Tests may force case-insensitive semantics on a case-sensitive host.  This
    policy is intentionally a guard concern, not a reducer concern.
    """

    case_sensitive: bool

    @classmethod
    def for_host(cls) -> "FilesystemIdentityPolicy":
        return cls(case_sensitive=os.name != "nt")

    @property
    def name(self) -> str:
        return "case_sensitive" if self.case_sensitive else "case_insensitive"

    def key_for_resolved_target(self, target: Path | str) -> str:
        value = os.path.normpath(str(target))
        normalized = value if self.case_sensitive else value.casefold()
        return f"{self.name}:{normalized}"


@dataclass(frozen=True)
class ValidatedTarget:
    """One durable physical identity returned for a canonical logical path."""

    relative_path: str
    resolved_target: str
    physical_identity_key: str


@dataclass(frozen=True)
class ValidatedWorkspaceTarget:
    """The validated workspace root and all bounded targets for one execution."""

    resolved_workspace: str
    identity_policy: FilesystemIdentityPolicy
    targets: tuple[ValidatedTarget, ...]

    def target_for(self, relative_path: str) -> ValidatedTarget:
        matches = [target for target in self.targets if target.relative_path == relative_path]
        if len(matches) != 1:
            raise WorkspaceGuardError("target_not_validated", "receipt path was not a validated executor target")
        return matches[0]


def _host_path_key(path: Path) -> str:
    """Use host semantics only for physical containment, never alias policy."""

    return os.path.normcase(os.path.normpath(str(path)))


def _is_beneath(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath([_host_path_key(root), _host_path_key(candidate)]) == _host_path_key(root)
    except ValueError:  # distinct drives on Windows
        return False


def _canonical_relative_path(relative_path: str) -> tuple[str, ...]:
    if not isinstance(relative_path, str) or not relative_path or relative_path != relative_path.strip():
        raise WorkspaceGuardError("invalid_relative_path", "operation path must be a non-empty canonical string")
    if "\x00" in relative_path or "\\" in relative_path:
        raise WorkspaceGuardError("invalid_relative_path", "operation path contains an ambiguous separator or NUL")
    windows = PureWindowsPath(relative_path)
    if windows.is_absolute() or windows.drive:
        raise WorkspaceGuardError("invalid_relative_path", "absolute and drive-relative operation paths are forbidden")
    posix = PurePosixPath(relative_path)
    if posix.is_absolute() or not posix.parts:
        raise WorkspaceGuardError("invalid_relative_path", "operation path must be relative")
    if any(
        part in {"", ".", ".."}
        or ":" in part  # ADS / alternate path syntax
        or part.endswith((".", " "))  # Windows trailing-dot/space aliases
        for part in posix.parts
    ):
        raise WorkspaceGuardError("invalid_relative_path", "operation path has traversal, ADS, or Windows alias syntax")
    canonical = "/".join(posix.parts)
    if canonical != relative_path:
        raise WorkspaceGuardError("invalid_relative_path", "operation path is not in canonical POSIX form")
    return posix.parts


@dataclass(frozen=True)
class WorkspaceGuard:
    """Resolve, contain, and identify executor targets outside the reducer."""

    target_workspace: str | Path
    policy: WorkspacePolicy | None = None
    identity_policy: FilesystemIdentityPolicy | None = None

    def _identity_policy(self) -> FilesystemIdentityPolicy:
        return self.identity_policy or FilesystemIdentityPolicy.for_host()

    def resolved_workspace(self) -> Path:
        raw = str(self.target_workspace).strip()
        if not raw:
            raise WorkspaceGuardError("workspace_unavailable", "configured target workspace is empty")
        root = Path(raw)
        if not root.exists() or not root.is_dir():
            raise WorkspaceGuardError("workspace_unavailable", "configured target workspace is missing or not a directory")
        try:
            return root.resolve(strict=True)
        except OSError as exc:
            raise WorkspaceGuardError("workspace_unavailable", f"configured target workspace cannot be resolved: {exc}") from exc

    def validate(self, relative_path: str) -> ValidatedTarget:
        parts = _canonical_relative_path(relative_path)
        if self.policy is not None and not self.policy.permits(relative_path):
            raise WorkspaceGuardError("workspace_policy_rejected", "operation path is rejected by configured workspace policy")
        root = self.resolved_workspace()
        current = root
        for part in parts:
            current = current / part
            # ``is_symlink`` catches broken links.  Resolvable junctions are
            # checked through the same physical containment rule.
            if current.exists() or current.is_symlink():
                try:
                    resolved_component = current.resolve(strict=True)
                except OSError as exc:
                    raise WorkspaceGuardError("unresolvable_component", f"workspace component cannot be resolved: {part}") from exc
                if not _is_beneath(root, resolved_component):
                    raise WorkspaceGuardError("workspace_escape", "operation path resolves outside the configured workspace")
        try:
            target = (root.joinpath(*parts)).resolve(strict=False)
        except OSError as exc:
            raise WorkspaceGuardError("unresolvable_target", "operation target cannot be resolved") from exc
        if not _is_beneath(root, target):
            raise WorkspaceGuardError("workspace_escape", "operation target resolves outside the configured workspace")
        return ValidatedTarget(
            relative_path=relative_path,
            resolved_target=str(target),
            physical_identity_key=self._identity_policy().key_for_resolved_target(target),
        )

    def validate_distinct(self, relative_paths: Iterable[str]) -> tuple[ValidatedTarget, ...]:
        """Validate a batch and reject different logical paths that alias."""

        targets: list[ValidatedTarget] = []
        seen: dict[str, str] = {}
        for relative_path in relative_paths:
            target = self.validate(relative_path)
            prior = seen.get(target.physical_identity_key)
            if prior is not None and prior != relative_path:
                raise WorkspaceGuardError(
                    "workspace_alias",
                    f"distinct operation paths alias one target: {prior!r} and {relative_path!r}",
                )
            seen[target.physical_identity_key] = relative_path
            targets.append(target)
        return tuple(targets)

    def validate_workspace_target(self, relative_paths: Iterable[str]) -> ValidatedWorkspaceTarget:
        """Return the complete immutable target set supplied to a trusted adapter."""

        root = self.resolved_workspace()
        return ValidatedWorkspaceTarget(
            resolved_workspace=str(root),
            identity_policy=self._identity_policy(),
            targets=self.validate_distinct(relative_paths),
        )
