"""Explicit physical live-workspace policy for V0 offline integration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from admissible.execution.bounded_write import (
    WorkspaceAuthorityDescriptor,
    physical_identity_key,
    revalidate_workspace_authority,
)


class WorkspaceIntegrationError(ValueError):
    """Reject a configured target workspace before a V0 session starts."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _path_key(path: Path) -> str:
    value = os.path.normpath(str(path))
    return value.casefold() if os.name == "nt" else value


def _is_beneath(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath([_path_key(root), _path_key(candidate)]) == _path_key(root)
    except ValueError:  # Windows drives / other incomparable roots
        return False


def _resolve_configured_root(raw: str, *, code: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise WorkspaceIntegrationError(code, "configured workspace root must be a non-empty path")
    candidate = Path(raw)
    if not candidate.exists() or not candidate.is_dir():
        raise WorkspaceIntegrationError(code, "configured workspace root must exist and be a directory")
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise WorkspaceIntegrationError(code, f"configured workspace root cannot be resolved: {exc}") from exc


@dataclass(frozen=True)
class WorkspaceIntegrationPolicy:
    """Configured physical live roots, with rejected artifacts taking priority."""

    allowed_target_categories: tuple[str, ...] = ("live_application",)
    allowed_live_workspace_roots: tuple[str, ...] = ()
    rejected_workspace_roots: tuple[str, ...] = ()

    def validate_target_workspace(self, target_workspace: str | Path) -> Path:
        authority = self.capture_workspace_authority(target_workspace)
        return Path(authority.canonical_workspace_path)

    def capture_workspace_authority(
        self,
        target_workspace: str | Path,
        *,
        case_sensitive: bool | None = None,
    ) -> WorkspaceAuthorityDescriptor:
        """Validate configuration and freeze its physical authority descriptor."""

        raw = str(target_workspace).strip()
        if not raw:
            raise WorkspaceIntegrationError("missing_workspace", "target workspace path is empty")
        root = Path(raw)
        if not root.exists() or not root.is_dir():
            raise WorkspaceIntegrationError("missing_workspace", "target workspace must exist and be a directory")
        try:
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise WorkspaceIntegrationError("missing_workspace", f"target workspace cannot be resolved: {exc}") from exc
        if "live_application" not in self.allowed_target_categories:
            raise WorkspaceIntegrationError("category_rejected", "configured workspace category is not permitted for live application targets")

        rejected_roots = tuple(
            (str(value).strip(), _resolve_configured_root(value, code="invalid_rejected_root"))
            for value in self.rejected_workspace_roots
        )
        if any(_is_beneath(rejected, resolved) for _, rejected in rejected_roots):
            raise WorkspaceIntegrationError(
                "artifact_root_rejected",
                "target workspace is an artifact-output root or is nested beneath one",
            )

        if not self.allowed_live_workspace_roots:
            raise WorkspaceIntegrationError("allowed_live_root_required", "at least one explicit allowed live-workspace root is required")
        allowed_roots = tuple(
            (str(value).strip(), _resolve_configured_root(value, code="invalid_allowed_live_root"))
            for value in self.allowed_live_workspace_roots
        )
        matches = tuple((configured, root) for configured, root in allowed_roots if _is_beneath(root, resolved))
        if not matches:
            raise WorkspaceIntegrationError("outside_allowed_live_root", "target workspace is outside every configured allowed live-workspace root")
        if len(matches) != 1:
            raise WorkspaceIntegrationError("ambiguous_allowed_live_root", "target workspace is beneath more than one configured allowed live-workspace root")
        configured_allowed, allowed = matches[0]
        resolved_case_sensitive = os.name != "nt" if case_sensitive is None else case_sensitive
        return WorkspaceAuthorityDescriptor(
            configured_workspace_path=raw,
            canonical_workspace_path=str(resolved),
            workspace_identity_key=physical_identity_key(resolved, case_sensitive=resolved_case_sensitive),
            configured_allowed_live_root_path=configured_allowed,
            canonical_allowed_live_root_path=str(allowed),
            allowed_live_root_identity_key=physical_identity_key(allowed, case_sensitive=resolved_case_sensitive),
            configured_rejected_root_paths=tuple(configured for configured, _ in rejected_roots),
            canonical_rejected_root_paths=tuple(str(root) for _, root in rejected_roots),
            rejected_root_identity_keys=tuple(
                physical_identity_key(root, case_sensitive=resolved_case_sensitive) for _, root in rejected_roots
            ),
            filesystem_case_sensitive=resolved_case_sensitive,
        )

    def revalidate_authority(self, authority: WorkspaceAuthorityDescriptor) -> Path:
        try:
            return revalidate_workspace_authority(authority)
        except ValueError as exc:
            diagnostic = getattr(exc, "diagnostic", "workspace_authority_changed")
            raise WorkspaceIntegrationError(str(diagnostic), str(exc)) from exc
