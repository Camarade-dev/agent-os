"""Deterministic, durable structural checks for V0 Slice 2 offline integration."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from admissible.v0_controller.commands import Command, CommandKind
from admissible.v0_controller.events import StructuralCheckCompleted
from admissible.v0_controller.state import OutcomeReason as StateOutcomeReason, ReasonCode, SessionState, StructuralFileCheck
from admissible.v0_controller.workspace_guard import WorkspaceGuard, WorkspaceGuardError


def _reason(code: ReasonCode, message: str, action: str) -> StateOutcomeReason:
    return StateOutcomeReason(code=code, message=message, operator_action=action)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class V0StructuralChecker:
    """Verify every mandatory path and persist the first bounded failure itself."""

    check_count: int = 0

    @staticmethod
    def _failed_check(
        *,
        command: Command,
        path: str,
        exists: bool,
        non_empty: bool,
        inside_workspace: bool,
        failure_code: str,
        expected_sha256: str | None,
        observed_sha256: str | None,
    ) -> StructuralFileCheck:
        return StructuralFileCheck(
            path=path,
            exists=exists,
            non_empty=non_empty,
            inside_workspace=inside_workspace,
            sha256=observed_sha256,
            structural_command_id=command.command_id or "",
            check_kind="mandatory_file",
            passed=False,
            failure_code=failure_code,
            expected_sha256=expected_sha256,
            observed_sha256=observed_sha256,
        )

    @staticmethod
    def _technical_failure(
        *,
        command: Command,
        checks: list[StructuralFileCheck],
        failure_code: str,
        path: str,
    ) -> StructuralCheckCompleted:
        return StructuralCheckCompleted(
            checks=tuple(checks),
            occurred_at=f"structural-check:{command.command_id}",
            technical_reason=_reason(
                ReasonCode.STRUCTURAL_CHECK_TECHNICAL,
                f"{failure_code}: mandatory path {path!r} failed structural verification.",
                "Inspect the persisted structural check record and start a new V0 session.",
            ),
        )

    def check(
        self,
        *,
        command: Command,
        state: SessionState,
        guard: WorkspaceGuard,
    ) -> StructuralCheckCompleted:
        if command.kind != CommandKind.RUN_STRUCTURAL_CHECK:
            raise ValueError("structural checker accepts run_structural_check commands only")
        guard.revalidate_authority()
        self.check_count += 1
        evidence_by_path = {item.path: item for item in state.materialized_evidence}
        checks: list[StructuralFileCheck] = []
        for path in state.mandatory_paths:
            guard.revalidate_authority()
            evidence = evidence_by_path.get(path)
            expected = None if evidence is None else evidence.sha256
            try:
                target = guard.validate(path)
            except WorkspaceGuardError:
                checks.append(
                    self._failed_check(
                        command=command,
                        path=path,
                        exists=False,
                        non_empty=False,
                        inside_workspace=False,
                        failure_code="containment_failure",
                        expected_sha256=expected,
                        observed_sha256=None,
                    )
                )
                return self._technical_failure(command=command, checks=checks, failure_code="containment_failure", path=path)

            resolved = Path(target.resolved_target)
            exists = resolved.exists()
            if not exists:
                checks.append(self._failed_check(
                    command=command, path=path, exists=False, non_empty=False, inside_workspace=True,
                    failure_code="file_missing", expected_sha256=expected, observed_sha256=None,
                ))
                return self._technical_failure(command=command, checks=checks, failure_code="file_missing", path=path)
            if not resolved.is_file():
                checks.append(self._failed_check(
                    command=command, path=path, exists=True, non_empty=False, inside_workspace=True,
                    failure_code="not_regular_file", expected_sha256=expected, observed_sha256=None,
                ))
                return self._technical_failure(command=command, checks=checks, failure_code="not_regular_file", path=path)
            if resolved.stat().st_size == 0:
                checks.append(self._failed_check(
                    command=command, path=path, exists=True, non_empty=False, inside_workspace=True,
                    failure_code="empty_file", expected_sha256=expected, observed_sha256=None,
                ))
                return self._technical_failure(command=command, checks=checks, failure_code="empty_file", path=path)
            observed = _sha256_file(resolved)
            if expected is not None and observed != expected:
                checks.append(self._failed_check(
                    command=command, path=path, exists=True, non_empty=True, inside_workspace=True,
                    failure_code="hash_mismatch", expected_sha256=expected, observed_sha256=observed,
                ))
                return self._technical_failure(command=command, checks=checks, failure_code="hash_mismatch", path=path)
            checks.append(
                StructuralFileCheck(
                    path=path,
                    exists=True,
                    non_empty=True,
                    inside_workspace=True,
                    sha256=observed,
                    structural_command_id=command.command_id or "",
                    check_kind="mandatory_file",
                    passed=True,
                    failure_code=None,
                    expected_sha256=expected,
                    observed_sha256=observed,
                )
            )
        return StructuralCheckCompleted(checks=tuple(checks), occurred_at=f"structural-check:{command.command_id}")
