"""Pure, closed-transition reducer for capsule product sessions.

CAPSULE_READY -> CAPSULE_EXECUTING -> PROVIDER_OUTPUT_FROZEN -> INTAKE_EVALUATING
  -> INTAKE_ACCEPTED -> VERIFYING_CHECKPOINT -> VERIFYING_BEHAVIOR
  -> FINALIZATION_READY -> FINALIZING -> ACCEPTED

Any non-terminal phase may instead resolve to REFUSED (an evidentiary
ruling: intake rejection, checkpoint refusal, or behavioral refusal) or
FAILED (an operational/transactional failure: provider failure, cleanup
failure, finalizer crash, or CAS refusal). Once a session reaches ACCEPTED,
REFUSED, or FAILED, no further event is legal — durable accepted effects
exist only after `FinalizationCompleted` with a PUBLISHED or
IDEMPOTENT_SAME_ACCEPTED_IDENTITY outcome is applied, and never earlier.

This reducer, its `Phase` enum, and its state are wholly independent of
`admissible.delegated_gate` — no historical run evidence or historical
`Phase` value is read, written, or reinterpreted here.
"""

from __future__ import annotations

from typing import Any

from admissible.capsule.events import (
    BehaviorVerified,
    CapsuleEvent,
    CapsuleExecutionStarted,
    CheckpointVerificationStarted,
    CheckpointVerified,
    FailureCode,
    FinalizationCompleted,
    FinalizationStarted,
    IntakeEvaluated,
    IntakeStarted,
    ProviderOutputFrozen,
    RefusalReason,
    SessionFailed,
)
from admissible.capsule.finalizer import FinalizationOutcome
from admissible.capsule.intake import AcceptedMaterialIdentity
from admissible.capsule.state import TERMINAL_PHASES, CapsuleSessionState, Phase, mint_state
from admissible.capsule.verification import require_independent_copies


class IllegalTransition(ValueError):
    pass


def _next(state: CapsuleSessionState, **changes: Any) -> CapsuleSessionState:
    values = {
        "schema_version": state.schema_version,
        "session_id": state.session_id,
        "revision": state.revision + 1,
        "phase": state.phase,
        "capsule_authority": state.capsule_authority,
        "provider_output": state.provider_output,
        "intake_evidence": state.intake_evidence,
        "accepted_material": state.accepted_material,
        "checkpoint_result": state.checkpoint_result,
        "behavior_result": state.behavior_result,
        "finalization_evidence": state.finalization_evidence,
        "durability_receipt": state.durability_receipt,
        "finalization_result": state.finalization_result,
        "refusal_reason": state.refusal_reason,
        "failure_code": state.failure_code,
        "failure_detail": state.failure_detail,
    }
    values.update(changes)
    return mint_state(**values)


def reduce(state: CapsuleSessionState, event: CapsuleEvent) -> CapsuleSessionState:
    """Apply one explicit protocol event; no other code may perform transitions."""

    state.validated_structure()

    if state.phase in TERMINAL_PHASES:
        raise IllegalTransition("no event is legal once a capsule session reaches a terminal phase")

    if isinstance(event, SessionFailed):
        return _next(state, phase=Phase.FAILED, failure_code=event.code, failure_detail=event.detail)

    if isinstance(event, CapsuleExecutionStarted):
        if state.phase != Phase.CAPSULE_READY:
            raise IllegalTransition("capsule execution may only start from CAPSULE_READY")
        return _next(state, phase=Phase.CAPSULE_EXECUTING)

    if isinstance(event, ProviderOutputFrozen):
        if state.phase != Phase.CAPSULE_EXECUTING:
            raise IllegalTransition("provider output can only be frozen while the capsule is executing")
        output = event.provider_output
        output.validated()
        if output.capsule_authority_fingerprint != state.capsule_authority.authority_fingerprint:
            raise IllegalTransition("provider output is bound to another capsule authority")
        return _next(state, phase=Phase.PROVIDER_OUTPUT_FROZEN, provider_output=output)

    if isinstance(event, IntakeStarted):
        if state.phase != Phase.PROVIDER_OUTPUT_FROZEN:
            raise IllegalTransition("intake can only start once provider output is frozen")
        return _next(state, phase=Phase.INTAKE_EVALUATING)

    if isinstance(event, IntakeEvaluated):
        if state.phase != Phase.INTAKE_EVALUATING:
            raise IllegalTransition("an intake ruling is not legal outside INTAKE_EVALUATING")
        evidence = event.intake_evidence
        evidence.validated()
        if evidence.ruling == "ACCEPTED":
            if not evidence.published:
                raise IllegalTransition("accepted intake is not durably published")
            accepted_material = AcceptedMaterialIdentity.from_intake_evidence(evidence)
            return _next(
                state,
                phase=Phase.INTAKE_ACCEPTED,
                intake_evidence=evidence,
                accepted_material=accepted_material,
            )
        return _next(
            state,
            phase=Phase.REFUSED,
            intake_evidence=evidence,
            refusal_reason=RefusalReason.INTAKE_REJECTED,
        )

    if isinstance(event, CheckpointVerificationStarted):
        if state.phase != Phase.INTAKE_ACCEPTED:
            raise IllegalTransition("checkpoint verification requires accepted intake")
        return _next(state, phase=Phase.VERIFYING_CHECKPOINT)

    if isinstance(event, CheckpointVerified):
        if state.phase != Phase.VERIFYING_CHECKPOINT:
            raise IllegalTransition("a checkpoint verdict is not legal outside VERIFYING_CHECKPOINT")
        result = event.checkpoint_result
        result.validated()
        if state.accepted_material is None or result.accepted_material != state.accepted_material:
            raise IllegalTransition("checkpoint verification is bound to different accepted material")
        if result.passed:
            # A checkpoint PASS never implies behavioral acceptance: entering
            # VERIFYING_BEHAVIOR only starts an independent verification pass.
            return _next(state, phase=Phase.VERIFYING_BEHAVIOR, checkpoint_result=result)
        return _next(
            state,
            phase=Phase.REFUSED,
            checkpoint_result=result,
            refusal_reason=RefusalReason.CHECKPOINT_REFUSED,
        )

    if isinstance(event, BehaviorVerified):
        if state.phase != Phase.VERIFYING_BEHAVIOR:
            raise IllegalTransition("a behavioral verdict is not legal outside VERIFYING_BEHAVIOR")
        if state.checkpoint_result is None or not state.checkpoint_result.passed:
            raise IllegalTransition("behavioral verification requires a passed checkpoint")
        result = event.behavior_result
        result.validated()
        if state.accepted_material is None or result.accepted_material != state.accepted_material:
            raise IllegalTransition("behavioral verification is bound to different accepted material")
        require_independent_copies(state.checkpoint_result.copy, result.copy)
        if result.passed:
            return _next(state, phase=Phase.FINALIZATION_READY, behavior_result=result)
        return _next(
            state,
            phase=Phase.REFUSED,
            behavior_result=result,
            refusal_reason=RefusalReason.BEHAVIOR_REFUSED,
        )

    if isinstance(event, FinalizationStarted):
        if state.phase != Phase.FINALIZATION_READY:
            raise IllegalTransition("finalization may only start once behavioral verification has passed")
        evidence = event.finalization_evidence
        receipt = event.durability_receipt
        evidence.validated()
        receipt.verify(evidence)
        if state.accepted_material is None or evidence.accepted_material != state.accepted_material:
            raise IllegalTransition("finalization authorization is bound to different accepted material")
        if receipt.store_authority != evidence.finalizer_authority.evidence_store_authority:
            raise IllegalTransition("finalization durability receipt belongs to another authority")
        return _next(
            state,
            phase=Phase.FINALIZING,
            finalization_evidence=evidence,
            durability_receipt=receipt,
        )

    if isinstance(event, FinalizationCompleted):
        if state.phase != Phase.FINALIZING:
            raise IllegalTransition("a finalization outcome is not legal outside FINALIZING")
        result = event.finalization_result
        result.validated()
        if state.finalization_evidence is None or state.durability_receipt is None:
            raise IllegalTransition("finalization completed without state authorization")
        if (
            result.accepted_material != state.accepted_material
            or result.expected_tree != state.finalization_evidence.expected_tree
            or result.finalizer_authority != state.finalization_evidence.finalizer_authority
            or result.parent != state.finalization_evidence.parent
            or result.publication_ref != state.finalization_evidence.publication_ref
            or result.resulting_commit != state.finalization_evidence.resulting_commit
            or result.durable_evidence != state.finalization_evidence
            or result.durability_receipt != state.durability_receipt
        ):
            raise IllegalTransition("finalization result differs from the transaction authorized by state")
        if result.outcome in (
            FinalizationOutcome.PUBLISHED,
            FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY,
        ):
            return _next(state, phase=Phase.ACCEPTED, finalization_result=result)
        return _next(
            state,
            phase=Phase.FAILED,
            finalization_result=result,
            failure_code=FailureCode.COMPARE_AND_SWAP_REFUSED,
            failure_detail="finalizer compare-and-swap update-ref was refused",
        )

    raise IllegalTransition(f"unsupported capsule event: {type(event).__name__}")
