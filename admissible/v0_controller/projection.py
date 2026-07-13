"""Pure, non-authoritative Control-Surface-friendly V0 state projection."""

from __future__ import annotations

from typing import Any

from admissible.v0_controller.state import SessionState


def project_control_surface(state: SessionState) -> dict[str, Any]:
    """Return a fresh UI dictionary and never mutate or persist authoritative state."""

    return {
        "schema_version": "admissible_v0_projection_v1",
        "session_id": state.session_id,
        "revision": state.revision,
        "semantic_state_version": state.semantic_state_version,
        "phase": state.phase.value,
        "mandatory_paths": list(state.mandatory_paths),
        "materialized_paths": [item.path for item in state.materialized_evidence],
        "remaining_paths": list(state.remaining_paths()),
        "active_invocation": None
        if state.current_invocation is None
        else {"invocation_id": state.current_invocation.invocation_id, "lifecycle": state.current_invocation.lifecycle.value},
        "pending_command": None
        if state.pending_command is None
        else {"command_id": state.pending_command.command_id, "kind": state.pending_command.kind.value, "status": state.pending_command.status.value},
        "outcome_reason": None if state.outcome_reason is None else state.outcome_reason.to_dict(),
    }
