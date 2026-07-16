"""Fail-closed whole-state invariants for delegated-gate sessions."""

from __future__ import annotations

from admissible.delegated_gate.models import Verdict
from admissible.delegated_gate.state import (
    DelegatedSessionState,
    HumanBoundaryReason,
    Phase,
)


class InvariantViolation(ValueError):
    pass


def _fail(message: str) -> None:
    raise InvariantViolation(message)


def _histories_for(state: DelegatedSessionState, gate_id: str):
    checkpoints = tuple(cp for cp in state.checkpoint_history if cp.gate_id == gate_id)
    audits = tuple(verdict for verdict in state.audit_history if verdict.gate_id == gate_id)
    return checkpoints, audits


def _validate_repair_authority(state: DelegatedSessionState, checkpoints, audits) -> None:
    authority = state.repair_authority
    if authority is None:
        return
    if not audits or audits[0].verdict != Verdict.FIX_REQUIRED:
        _fail("repair authority requires an initial FIX_REQUIRED verdict")
    source = audits[0]
    accepted = tuple(f.finding_id for f in source.findings if f.enforceable_repair)
    surface = tuple(
        dict.fromkeys(
            item
            for finding in source.findings
            if finding.enforceable_repair
            for item in finding.bounded_repair_surface
        )
    )
    if (
        authority.gate_id != state.current_gate.gate_id
        or authority.checkpoint_fingerprint != checkpoints[0].checkpoint_fingerprint
        or authority.source_verdict_fingerprint != source.verdict_fingerprint
        or authority.accepted_finding_ids != accepted
        or authority.bounded_repair_surface != surface
    ):
        _fail("repair authority exceeds or differs from the exact accepted findings")


def validate_state(state: DelegatedSessionState) -> None:
    """Validate every durable authority value and the complete protocol history."""

    try:
        state.validated_structure()
    except (TypeError, ValueError) as exc:
        raise InvariantViolation(str(exc)) from exc

    gates = state.gate_plan.ordered_gate_contracts
    gate_index = {gate.gate_id: index for index, gate in enumerate(gates)}

    checkpoint_gate_order: list[int] = []
    for checkpoint in state.checkpoint_history:
        if checkpoint.session_id != state.session_id or checkpoint.gate_id not in gate_index:
            _fail("checkpoint is bound outside the immutable session plan")
        checkpoint_gate_order.append(gate_index[checkpoint.gate_id])
    if checkpoint_gate_order != sorted(checkpoint_gate_order):
        _fail("checkpoint history reorders immutable gates")

    audit_gate_order: list[int] = []
    for verdict in state.audit_history:
        if verdict.session_id != state.session_id or verdict.gate_id not in gate_index:
            _fail("audit verdict is bound outside the immutable session plan")
        audit_gate_order.append(gate_index[verdict.gate_id])
    if audit_gate_order != sorted(audit_gate_order):
        _fail("audit history reorders immutable gates")

    for index, gate in enumerate(gates):
        checkpoints, audits = _histories_for(state, gate.gate_id)
        if len(checkpoints) > 2 or len(audits) > 2:
            _fail("a gate exceeded one execution plus one repair/re-audit")
        if tuple(cp.execution_attempt_index for cp in checkpoints) not in {(), (0,), (0, 1)}:
            _fail("checkpoint attempts are not the fixed initial/repair sequence")
        if len(audits) > len(checkpoints):
            _fail("audit exists without a material checkpoint")
        for audit_position, verdict in enumerate(audits):
            checkpoint = checkpoints[audit_position]
            try:
                verdict.validate_against(contract=gate, checkpoint=checkpoint)
            except ValueError as exc:
                raise InvariantViolation(str(exc)) from exc
        if len(checkpoints) == 2:
            if gate.repair_budget != 1 or not audits or audits[0].verdict != Verdict.FIX_REQUIRED:
                _fail("repair checkpoint lacks exact initial repair authority")
        if len(audits) == 2 and audits[0].verdict != Verdict.FIX_REQUIRED:
            _fail("re-audit requires an initial FIX_REQUIRED verdict")
        if index < state.current_gate_index:
            if not audits or audits[-1].verdict != Verdict.PASS or len(checkpoints) != len(audits):
                _fail("a prior gate was advanced without PASS")
        elif index > state.current_gate_index and (checkpoints or audits):
            _fail("future immutable gates cannot have protocol history")

    checkpoints, audits = _histories_for(state, state.current_gate.gate_id)
    phase = state.phase
    _validate_repair_authority(state, checkpoints, audits)

    if phase == Phase.READY_FOR_GATE:
        if checkpoints or audits or state.repair_authority is not None:
            _fail("READY_FOR_GATE cannot retain current-gate work")
    elif phase == Phase.GATE_EXECUTING:
        if checkpoints or audits or state.repair_authority is not None:
            _fail("initial gate execution cannot retain checkpoint/audit authority")
    elif phase == Phase.CHECKPOINT_CAPTURED:
        if len(checkpoints) != len(audits) + 1 or len(checkpoints) not in (1, 2):
            _fail("CHECKPOINT_CAPTURED requires exactly one unaudited checkpoint")
        if len(checkpoints) == 2 and state.repair_authority is None:
            _fail("repair checkpoint requires retained exact repair authority")
    elif phase == Phase.AUDITING:
        if len(checkpoints) != 1 or audits or state.repair_authority is not None:
            _fail("AUDITING is only the first audit of attempt zero")
    elif phase in {Phase.REPAIR_AUTHORIZED, Phase.REPAIR_EXECUTING}:
        if (
            len(checkpoints) != 1
            or len(audits) != 1
            or audits[0].verdict != Verdict.FIX_REQUIRED
            or state.repair_authority is None
        ):
            _fail("repair phase lacks one exact FIX_REQUIRED authority")
    elif phase == Phase.REAUDITING:
        if (
            len(checkpoints) != 2
            or len(audits) != 1
            or audits[0].verdict != Verdict.FIX_REQUIRED
            or state.repair_authority is None
        ):
            _fail("REAUDITING requires one repair checkpoint and no prior re-audit")
    elif phase == Phase.GATE_PASSED:
        if not audits or len(checkpoints) != len(audits) or audits[-1].verdict != Verdict.PASS:
            _fail("GATE_PASSED requires the current checkpoint audit to PASS")
    elif phase == Phase.AWAITING_HUMAN:
        if state.human_boundary_reason is None or state.human_disposition is not None:
            _fail("AWAITING_HUMAN requires a reason and no disposition")
        if not audits or len(checkpoints) != len(audits):
            _fail("human boundary requires a completed audit")
        last = audits[-1].verdict
        reason = state.human_boundary_reason
        if reason == HumanBoundaryReason.FINAL_REVIEW:
            if state.current_gate_index != len(gates) - 1 or last != Verdict.PASS:
                _fail("final human review requires final predefined gate PASS")
        elif reason == HumanBoundaryReason.BLOCKED:
            if len(audits) != 1 or last != Verdict.BLOCKED:
                _fail("BLOCKED human boundary is inconsistent")
        elif reason == HumanBoundaryReason.INCONCLUSIVE:
            if len(audits) != 1 or last != Verdict.INCONCLUSIVE:
                _fail("INCONCLUSIVE human boundary is inconsistent")
        elif reason == HumanBoundaryReason.REPAIR_BUDGET_UNAVAILABLE:
            if len(audits) != 1 or last != Verdict.FIX_REQUIRED or state.current_gate.repair_budget != 0:
                _fail("repair-budget human boundary is inconsistent")
        elif reason == HumanBoundaryReason.FAILED_REAUDIT:
            if len(audits) != 2 or last == Verdict.PASS:
                _fail("failed re-audit human boundary is inconsistent")
    elif phase == Phase.COMPLETED:
        if (
            state.human_boundary_reason != HumanBoundaryReason.FINAL_REVIEW
            or state.human_disposition is None
            or state.current_gate_index != len(gates) - 1
            or not audits
            or audits[-1].verdict != Verdict.PASS
            or len(checkpoints) != len(audits)
        ):
            _fail("COMPLETED requires write-once human acceptance after final gate PASS")
    else:  # pragma: no cover - Enum construction rejects this first
        _fail("unknown delegated session phase")

    if phase not in {Phase.AWAITING_HUMAN, Phase.COMPLETED}:
        if state.human_boundary_reason is not None or state.human_disposition is not None:
            _fail("human authority exists outside a human-boundary phase")
