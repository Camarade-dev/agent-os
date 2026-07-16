"""Pure, closed-transition reducer for delegated-gate sessions."""

from __future__ import annotations

from typing import Any

from admissible.delegated_gate.checkpoint import _consume_issued_checkpoint, _peek_issued_checkpoint
from admissible.delegated_gate.events import (
    AuditStarted,
    AuditVerdictRecorded,
    CheckpointRecorded,
    DelegatedEvent,
    GateAdvanced,
    GateExecutionStarted,
    HumanDispositionRecorded,
    RepairExecutionStarted,
)
from admissible.delegated_gate.invariants import validate_state
from admissible.delegated_gate.models import CommandEvidence, Verdict
from admissible.delegated_gate.state import (
    DelegatedSessionState,
    HumanBoundaryReason,
    Phase,
    RepairAuthority,
    mint_state,
)


class IllegalTransition(ValueError):
    pass


def _next(state: DelegatedSessionState, **changes: Any) -> DelegatedSessionState:
    values = {
        "schema_version": state.schema_version,
        "session_id": state.session_id,
        "revision": state.revision + 1,
        "phase": state.phase,
        "mission": state.mission,
        "gate_plan": state.gate_plan,
        "current_gate_index": state.current_gate_index,
        "checkpoint_history": state.checkpoint_history,
        "audit_history": state.audit_history,
        "repair_authority": state.repair_authority,
        "human_boundary_reason": state.human_boundary_reason,
        "human_disposition": state.human_disposition,
    }
    values.update(changes)
    result = mint_state(**values)
    validate_state(result)
    return result


def _repair_authority(verdict) -> RepairAuthority:
    findings = tuple(finding for finding in verdict.findings if finding.enforceable_repair)
    return RepairAuthority(
        gate_id=verdict.gate_id,
        checkpoint_fingerprint=verdict.checkpoint_fingerprint,
        source_verdict_fingerprint=verdict.verdict_fingerprint,
        accepted_finding_ids=tuple(finding.finding_id for finding in findings),
        bounded_repair_surface=tuple(
            dict.fromkeys(item for finding in findings for item in finding.bounded_repair_surface)
        ),
    ).validated()


def _validate_checkpoint_contract(state: DelegatedSessionState, checkpoint) -> None:
    gate = state.current_gate
    checkpoint.validated()
    if checkpoint.session_id != state.session_id or checkpoint.gate_id != gate.gate_id:
        raise IllegalTransition("checkpoint identity is bound to another session or gate")
    expected_attempt = 0 if state.phase == Phase.GATE_EXECUTING else 1
    if checkpoint.execution_attempt_index != expected_attempt:
        raise IllegalTransition("checkpoint execution attempt does not match the active phase")
    if not set(gate.required_evidence_kinds).issubset(checkpoint.evidence_kinds):
        raise IllegalTransition("checkpoint omits contract-required evidence kinds")
    command_records = tuple(
        record for record in checkpoint.evidence_records if isinstance(record, CommandEvidence)
    )
    declared = gate.checkpoint_verification_commands
    if len(command_records) != len(declared):
        raise IllegalTransition("checkpoint command evidence does not match the fixed contract")
    for record, command in zip(command_records, declared):
        if record.command_id != command.command_id or record.argv != command.argv:
            raise IllegalTransition("checkpoint command evidence rewrites the fixed contract")


def reduce(state: DelegatedSessionState, event: DelegatedEvent) -> DelegatedSessionState:
    """Apply one explicit protocol event; no other code may perform transitions."""

    validate_state(state)

    if isinstance(event, GateExecutionStarted):
        if state.phase != Phase.READY_FOR_GATE or event.gate_id != state.current_gate.gate_id:
            raise IllegalTransition("only the current predefined gate may start")
        return _next(state, phase=Phase.GATE_EXECUTING)

    if isinstance(event, CheckpointRecorded):
        if state.phase not in {Phase.GATE_EXECUTING, Phase.REPAIR_EXECUTING}:
            raise IllegalTransition("checkpoint capture is not legal in this phase")
        expected_attempt = 0 if state.phase == Phase.GATE_EXECUTING else 1
        try:
            checkpoint = _peek_issued_checkpoint(
                event.capture_result,
                session_id=state.session_id,
                gate_id=state.current_gate.gate_id,
                execution_attempt_index=expected_attempt,
            )
            _validate_checkpoint_contract(state, checkpoint)
        except ValueError as exc:
            raise IllegalTransition(str(exc)) from exc
        result = _next(
            state,
            phase=Phase.CHECKPOINT_CAPTURED,
            checkpoint_history=state.checkpoint_history + (checkpoint,),
        )
        try:
            _consume_issued_checkpoint(
                event.capture_result,
                session_id=state.session_id,
                gate_id=state.current_gate.gate_id,
                execution_attempt_index=expected_attempt,
                checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
            )
        except ValueError as exc:  # defensive: an in-process replay race fails closed
            raise IllegalTransition(str(exc)) from exc
        return result

    if isinstance(event, AuditStarted):
        if state.phase != Phase.CHECKPOINT_CAPTURED:
            raise IllegalTransition("audit requires a durable material checkpoint")
        checkpoints = tuple(
            cp for cp in state.checkpoint_history if cp.gate_id == state.current_gate.gate_id
        )
        return _next(
            state,
            phase=(Phase.AUDITING if checkpoints[-1].execution_attempt_index == 0 else Phase.REAUDITING),
        )

    if isinstance(event, AuditVerdictRecorded):
        if state.phase not in {Phase.AUDITING, Phase.REAUDITING}:
            raise IllegalTransition("audit verdict is not legal in this phase")
        checkpoints = tuple(
            cp for cp in state.checkpoint_history if cp.gate_id == state.current_gate.gate_id
        )
        checkpoint = checkpoints[-1]
        try:
            event.audit_verdict.validate_against(
                contract=state.current_gate,
                checkpoint=checkpoint,
            )
        except ValueError as exc:
            raise IllegalTransition(str(exc)) from exc
        history = state.audit_history + (event.audit_verdict,)
        verdict = event.audit_verdict.verdict
        if state.phase == Phase.REAUDITING:
            if verdict == Verdict.PASS:
                return _next(state, phase=Phase.GATE_PASSED, audit_history=history)
            return _next(
                state,
                phase=Phase.AWAITING_HUMAN,
                audit_history=history,
                human_boundary_reason=HumanBoundaryReason.FAILED_REAUDIT,
            )
        if verdict == Verdict.PASS:
            return _next(state, phase=Phase.GATE_PASSED, audit_history=history)
        if verdict == Verdict.FIX_REQUIRED:
            if state.current_gate.repair_budget == 0:
                return _next(
                    state,
                    phase=Phase.AWAITING_HUMAN,
                    audit_history=history,
                    human_boundary_reason=HumanBoundaryReason.REPAIR_BUDGET_UNAVAILABLE,
                )
            return _next(
                state,
                phase=Phase.REPAIR_AUTHORIZED,
                audit_history=history,
                repair_authority=_repair_authority(event.audit_verdict),
            )
        if verdict == Verdict.BLOCKED:
            return _next(
                state,
                phase=Phase.AWAITING_HUMAN,
                audit_history=history,
                human_boundary_reason=HumanBoundaryReason.BLOCKED,
            )
        return _next(
            state,
            phase=Phase.AWAITING_HUMAN,
            audit_history=history,
            human_boundary_reason=HumanBoundaryReason.INCONCLUSIVE,
        )

    if isinstance(event, RepairExecutionStarted):
        if state.phase != Phase.REPAIR_AUTHORIZED:
            raise IllegalTransition("repair may start exactly once from explicit authority")
        return _next(state, phase=Phase.REPAIR_EXECUTING)

    if isinstance(event, GateAdvanced):
        if state.phase != Phase.GATE_PASSED:
            raise IllegalTransition("only a passed gate may advance")
        if state.current_gate_index + 1 < len(state.gate_plan.ordered_gate_contracts):
            return _next(
                state,
                phase=Phase.READY_FOR_GATE,
                current_gate_index=state.current_gate_index + 1,
                repair_authority=None,
            )
        return _next(
            state,
            phase=Phase.AWAITING_HUMAN,
            human_boundary_reason=HumanBoundaryReason.FINAL_REVIEW,
        )

    if isinstance(event, HumanDispositionRecorded):
        if (
            state.phase != Phase.AWAITING_HUMAN
            or state.human_boundary_reason != HumanBoundaryReason.FINAL_REVIEW
            or state.human_disposition is not None
        ):
            raise IllegalTransition("final acceptance is write-once at the final human boundary")
        event.disposition.validated()
        return _next(
            state,
            phase=Phase.COMPLETED,
            human_disposition=event.disposition,
        )

    raise IllegalTransition(f"unsupported delegated-gate event: {type(event).__name__}")
