"""Read-only integration projection for V0 Slice 2 offline runs."""

from __future__ import annotations

from typing import Any

from admissible.v0_controller.state import SessionState


def project_integration_run(
    state: SessionState,
    *,
    backend_invocations: int = 0,
    proposal_results_consumed: int = 0,
    bounded_writes: int = 0,
    duplicate_writes: int = 0,
    structural_checks: int = 0,
) -> dict[str, Any]:
    partial_batches = sum(
        1
        for batch in state.batch_history
        if batch.status.value == "completed" and batch.remaining_mandatory_paths
    )
    completed_batches = sum(1 for batch in state.batch_history if batch.status.value == "completed")
    interrupted_batches = sum(1 for batch in state.batch_history if batch.status.value == "interrupted")
    admitted_operations = sum(len(batch.admitted_operation_ids) for batch in state.batch_history)
    if state.current_batch is not None:
        admitted_operations += len(state.current_batch.admitted_operation_ids)
    return {
        "schema_version": "admissible_v0_integration_projection_v1",
        "session_id": state.session_id,
        "phase": state.phase.value,
        "revision": state.revision,
        "semantic_state_version": state.semantic_state_version,
        "backend_invocations": backend_invocations,
        "proposal_results_consumed": proposal_results_consumed,
        "admitted_operations": admitted_operations,
        "bounded_writes": len(state.execution_receipt_history),
        "adapter_observed_bounded_writes": bounded_writes,
        "duplicate_writes": duplicate_writes,
        "partial_batches": partial_batches,
        "completed_batches": completed_batches,
        "interrupted_batches": interrupted_batches,
        "structural_checks": structural_checks,
        "materialized_paths": [item.path for item in state.materialized_evidence],
        "execution_receipt_ids": [receipt.receipt_id for receipt in state.execution_receipt_history],
        "remaining_paths": list(state.remaining_paths()),
        "structural_verification_present": state.structural_verification is not None,
        "pending_command_kind": None if state.pending_command is None else state.pending_command.kind.value,
    }
