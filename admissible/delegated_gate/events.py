"""Closed event vocabulary consumed by the delegated-gate reducer."""

from __future__ import annotations

from dataclasses import dataclass

from admissible.delegated_gate.models import AuditVerdict
from admissible.delegated_gate.state import HumanDisposition


@dataclass(frozen=True)
class GateExecutionStarted:
    gate_id: str


@dataclass(frozen=True)
class CheckpointRecorded:
    capture_result: object


@dataclass(frozen=True)
class AuditStarted:
    pass


@dataclass(frozen=True)
class AuditVerdictRecorded:
    audit_verdict: AuditVerdict


@dataclass(frozen=True)
class RepairExecutionStarted:
    pass


@dataclass(frozen=True)
class GateAdvanced:
    pass


@dataclass(frozen=True)
class HumanDispositionRecorded:
    disposition: HumanDisposition


DelegatedEvent = (
    GateExecutionStarted
    | CheckpointRecorded
    | AuditStarted
    | AuditVerdictRecorded
    | RepairExecutionStarted
    | GateAdvanced
    | HumanDispositionRecorded
)
