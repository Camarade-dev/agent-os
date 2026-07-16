"""Deterministic test adapters; these are not native executor/auditor implementations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from admissible.delegated_gate.canonical import require_safe_relative_path
from admissible.delegated_gate.models import (
    AuditFinding,
    AuditVerdict,
    Checkpoint,
    EvidenceKind,
    GateContract,
    Mission,
    Verdict,
)


@dataclass(frozen=True)
class FixtureChange:
    relative_path: str
    content: bytes

    def __post_init__(self) -> None:
        require_safe_relative_path(self.relative_path, "fixture change path")
        if not isinstance(self.content, bytes):
            raise ValueError("fixture content must be bytes")


class FixtureExecutor:
    """Materialize a predefined test change set, with no shell or model autonomy."""

    def __init__(self, changes_by_attempt: dict[int, tuple[FixtureChange, ...]]) -> None:
        if set(changes_by_attempt) - {0, 1}:
            raise ValueError("fixture executor supports only initial and repair attempts")
        self._changes = {index: tuple(changes) for index, changes in changes_by_attempt.items()}

    def execute(self, *, repository: str | Path, execution_attempt_index: int) -> None:
        root = Path(repository).resolve()
        for change in self._changes.get(execution_attempt_index, ()):
            target = (root / change.relative_path).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ValueError("fixture change escapes repository") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(change.content)


class FixtureAuditor:
    """Return predefined typed verdicts from the deliberately transcript-free input."""

    def __init__(self, *, invocation_identity: str) -> None:
        self.invocation_identity = invocation_identity

    def audit(
        self,
        *,
        mission: Mission,
        gate_contract: GateContract,
        checkpoint: Checkpoint,
        required_evidence_kinds: tuple[EvidenceKind, ...],
        verdict: Verdict,
        findings: tuple[AuditFinding, ...] = (),
    ) -> AuditVerdict:
        # There is intentionally no executor transcript or executor narrative
        # parameter. This adapter is deterministic test machinery, not a model.
        mission.validated()
        gate_contract.validated()
        checkpoint.validated()
        if required_evidence_kinds != gate_contract.required_evidence_kinds:
            raise ValueError("auditor input must use the exact required evidence declaration")
        if not set(required_evidence_kinds).issubset(checkpoint.evidence_kinds):
            raise ValueError("checkpoint lacks auditor-required evidence")
        result = AuditVerdict.create(
            session_id=checkpoint.session_id,
            gate_id=gate_contract.gate_id,
            checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
            auditor_invocation_identity=self.invocation_identity,
            verdict=verdict,
            findings=findings,
        )
        return result.validate_against(contract=gate_contract, checkpoint=checkpoint)
